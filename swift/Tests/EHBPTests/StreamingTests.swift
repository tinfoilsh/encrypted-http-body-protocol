import XCTest
@testable import EHBP

/// Tests for streaming buffer management and multi-chunk decryption
final class StreamingTests: XCTestCase {

    // MARK: - Buffer Index Safety Tests

    /// Verifies that [UInt8] array maintains 0-based indices after removeFirst
    /// This is the core fix for the Data index bug
    func testArrayRemoveFirstMaintainsZeroBasedIndices() {
        var buffer = [UInt8]()

        // Append first chunk
        buffer.append(contentsOf: [0x00, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF])

        // Parse length using [0], [1], [2], [3]
        let length1 = Int(buffer[0]) << 24 |
                      Int(buffer[1]) << 16 |
                      Int(buffer[2]) << 8 |
                      Int(buffer[3])
        XCTAssertEqual(length1, 4)

        // Consume the chunk
        buffer.removeFirst(4 + length1)
        XCTAssertEqual(buffer.count, 0)

        // Append second chunk
        buffer.append(contentsOf: [0x00, 0x00, 0x00, 0x02, 0xCA, 0xFE])

        // After removeFirst + append, indices should still be 0-based
        // This is the key property that [UInt8] provides but Data does not
        let length2 = Int(buffer[0]) << 24 |
                      Int(buffer[1]) << 16 |
                      Int(buffer[2]) << 8 |
                      Int(buffer[3])
        XCTAssertEqual(length2, 2, "Second chunk length should be 2")

        // Verify we can access the data correctly
        XCTAssertEqual(buffer[4], 0xCA)
        XCTAssertEqual(buffer[5], 0xFE)
    }

    /// Simulates the exact streaming pattern from Client.swift requestStream
    func testStreamingBufferPattern() throws {
        let exportedSecret = Data(repeating: 0xAB, count: 32)
        let requestEnc = Data(repeating: 0xCD, count: 32)
        let responseNonce = Data(repeating: 0xEF, count: 32)

        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        // Create 3 chunks with different content
        let plaintexts = [
            Data("First chunk".utf8),
            Data("Second chunk with more data".utf8),
            Data("Third".utf8)
        ]

        // Encrypt and frame each chunk
        var framedData = [UInt8]()
        for (i, plaintext) in plaintexts.enumerated() {
            let ciphertext = try encryptChunk(keyMaterial: keyMaterial, seq: UInt64(i), plaintext: plaintext)
            // Add 4-byte length prefix (big-endian)
            let length = UInt32(ciphertext.count)
            framedData.append(UInt8((length >> 24) & 0xFF))
            framedData.append(UInt8((length >> 16) & 0xFF))
            framedData.append(UInt8((length >> 8) & 0xFF))
            framedData.append(UInt8(length & 0xFF))
            framedData.append(contentsOf: ciphertext)
        }

        // Now simulate the streaming decryption pattern from Client.swift
        var buffer = [UInt8]()
        var seq: UInt64 = 0
        var decryptedChunks = [Data]()

        // Feed bytes one at a time (simulating async byte stream)
        for byte in framedData {
            buffer.append(byte)

            // This is the exact logic from Client.swift lines 184-210
            while buffer.count >= 4 {
                let chunkLength = Int(buffer[0]) << 24 |
                                  Int(buffer[1]) << 16 |
                                  Int(buffer[2]) << 8 |
                                  Int(buffer[3])

                if chunkLength == 0 {
                    buffer.removeFirst(4)
                    continue
                }

                guard buffer.count >= 4 + chunkLength else {
                    break
                }

                let ciphertext = Data(buffer[4..<(4 + chunkLength)])
                buffer.removeFirst(4 + chunkLength)

                let plaintext = try decryptChunk(
                    keyMaterial: keyMaterial,
                    seq: seq,
                    ciphertext: ciphertext
                )
                seq += 1

                decryptedChunks.append(plaintext)
            }
        }

        // Verify all chunks were decrypted correctly
        XCTAssertEqual(decryptedChunks.count, 3, "Should have decrypted 3 chunks")
        XCTAssertEqual(decryptedChunks[0], plaintexts[0])
        XCTAssertEqual(decryptedChunks[1], plaintexts[1])
        XCTAssertEqual(decryptedChunks[2], plaintexts[2])
    }

    /// Test handling of zero-length chunks in streaming
    func testStreamingWithZeroLengthChunks() throws {
        let exportedSecret = Data(repeating: 0xAB, count: 32)
        let requestEnc = Data(repeating: 0xCD, count: 32)
        let responseNonce = Data(repeating: 0xEF, count: 32)

        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        let plaintext = Data("Real data".utf8)
        let ciphertext = try encryptChunk(keyMaterial: keyMaterial, seq: 0, plaintext: plaintext)

        // Create framed data with zero-length chunks interspersed
        var framedData = [UInt8]()

        // Zero-length chunk
        framedData.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // Real chunk
        let length = UInt32(ciphertext.count)
        framedData.append(UInt8((length >> 24) & 0xFF))
        framedData.append(UInt8((length >> 16) & 0xFF))
        framedData.append(UInt8((length >> 8) & 0xFF))
        framedData.append(UInt8(length & 0xFF))
        framedData.append(contentsOf: ciphertext)

        // Another zero-length chunk
        framedData.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // Simulate streaming decryption
        var buffer = [UInt8]()
        var seq: UInt64 = 0
        var decryptedChunks = [Data]()

        for byte in framedData {
            buffer.append(byte)

            while buffer.count >= 4 {
                let chunkLength = Int(buffer[0]) << 24 |
                                  Int(buffer[1]) << 16 |
                                  Int(buffer[2]) << 8 |
                                  Int(buffer[3])

                if chunkLength == 0 {
                    buffer.removeFirst(4)
                    continue
                }

                guard buffer.count >= 4 + chunkLength else {
                    break
                }

                let ct = Data(buffer[4..<(4 + chunkLength)])
                buffer.removeFirst(4 + chunkLength)

                let pt = try decryptChunk(keyMaterial: keyMaterial, seq: seq, ciphertext: ct)
                seq += 1
                decryptedChunks.append(pt)
            }
        }

        XCTAssertEqual(decryptedChunks.count, 1)
        XCTAssertEqual(decryptedChunks[0], plaintext)
        XCTAssertEqual(seq, 1, "Only one real chunk should have been processed")
    }

    /// Test with partial chunk arrival (simulating network fragmentation)
    func testStreamingWithFragmentedChunks() throws {
        let exportedSecret = Data(repeating: 0xAB, count: 32)
        let requestEnc = Data(repeating: 0xCD, count: 32)
        let responseNonce = Data(repeating: 0xEF, count: 32)

        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        let plaintext = Data("Test message for fragmentation".utf8)
        let ciphertext = try encryptChunk(keyMaterial: keyMaterial, seq: 0, plaintext: plaintext)

        // Frame the chunk
        var framedData = [UInt8]()
        let length = UInt32(ciphertext.count)
        framedData.append(UInt8((length >> 24) & 0xFF))
        framedData.append(UInt8((length >> 16) & 0xFF))
        framedData.append(UInt8((length >> 8) & 0xFF))
        framedData.append(UInt8(length & 0xFF))
        framedData.append(contentsOf: ciphertext)

        // Simulate receiving data in fragments of varying sizes
        let fragmentSizes = [1, 2, 3, 5, 7, 11, 13, 100] // Various fragment sizes
        var offset = 0
        var buffer = [UInt8]()
        var seq: UInt64 = 0
        var decryptedChunks = [Data]()

        for fragmentSize in fragmentSizes {
            // Add fragment to buffer
            let endOffset = min(offset + fragmentSize, framedData.count)
            if offset < framedData.count {
                buffer.append(contentsOf: framedData[offset..<endOffset])
                offset = endOffset
            }

            // Try to parse complete chunks
            while buffer.count >= 4 {
                let chunkLength = Int(buffer[0]) << 24 |
                                  Int(buffer[1]) << 16 |
                                  Int(buffer[2]) << 8 |
                                  Int(buffer[3])

                if chunkLength == 0 {
                    buffer.removeFirst(4)
                    continue
                }

                guard buffer.count >= 4 + chunkLength else {
                    break
                }

                let ct = Data(buffer[4..<(4 + chunkLength)])
                buffer.removeFirst(4 + chunkLength)

                let pt = try decryptChunk(keyMaterial: keyMaterial, seq: seq, ciphertext: ct)
                seq += 1
                decryptedChunks.append(pt)
            }
        }

        XCTAssertEqual(decryptedChunks.count, 1)
        XCTAssertEqual(decryptedChunks[0], plaintext)
    }

    /// Test large number of chunks to stress test buffer management
    func testStreamingManyChunks() throws {
        let exportedSecret = Data(repeating: 0xAB, count: 32)
        let requestEnc = Data(repeating: 0xCD, count: 32)
        let responseNonce = Data(repeating: 0xEF, count: 32)

        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        let chunkCount = 100
        var plaintexts = [Data]()
        var framedData = [UInt8]()

        // Create and frame many chunks
        for i in 0..<chunkCount {
            let plaintext = Data("Chunk \(i) with some padding data".utf8)
            plaintexts.append(plaintext)

            let ciphertext = try encryptChunk(keyMaterial: keyMaterial, seq: UInt64(i), plaintext: plaintext)
            let length = UInt32(ciphertext.count)
            framedData.append(UInt8((length >> 24) & 0xFF))
            framedData.append(UInt8((length >> 16) & 0xFF))
            framedData.append(UInt8((length >> 8) & 0xFF))
            framedData.append(UInt8(length & 0xFF))
            framedData.append(contentsOf: ciphertext)
        }

        // Decrypt all chunks
        var buffer = [UInt8]()
        var seq: UInt64 = 0
        var decryptedChunks = [Data]()

        for byte in framedData {
            buffer.append(byte)

            while buffer.count >= 4 {
                let chunkLength = Int(buffer[0]) << 24 |
                                  Int(buffer[1]) << 16 |
                                  Int(buffer[2]) << 8 |
                                  Int(buffer[3])

                if chunkLength == 0 {
                    buffer.removeFirst(4)
                    continue
                }

                guard buffer.count >= 4 + chunkLength else {
                    break
                }

                let ct = Data(buffer[4..<(4 + chunkLength)])
                buffer.removeFirst(4 + chunkLength)

                let pt = try decryptChunk(keyMaterial: keyMaterial, seq: seq, ciphertext: ct)
                seq += 1
                decryptedChunks.append(pt)
            }
        }

        XCTAssertEqual(decryptedChunks.count, chunkCount)
        for i in 0..<chunkCount {
            XCTAssertEqual(decryptedChunks[i], plaintexts[i], "Chunk \(i) mismatch")
        }
    }

    /// Test that wrong sequence number causes decryption failure in streaming context
    func testStreamingSequenceMismatchFails() throws {
        let exportedSecret = Data(repeating: 0xAB, count: 32)
        let requestEnc = Data(repeating: 0xCD, count: 32)
        let responseNonce = Data(repeating: 0xEF, count: 32)

        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        // Encrypt chunk 0
        let plaintext = Data("Test".utf8)
        let ciphertext = try encryptChunk(keyMaterial: keyMaterial, seq: 0, plaintext: plaintext)

        // Try to decrypt with wrong sequence
        XCTAssertThrowsError(try decryptChunk(keyMaterial: keyMaterial, seq: 1, ciphertext: ciphertext))
        XCTAssertThrowsError(try decryptChunk(keyMaterial: keyMaterial, seq: 99, ciphertext: ciphertext))

        // Correct sequence should work
        let decrypted = try decryptChunk(keyMaterial: keyMaterial, seq: 0, ciphertext: ciphertext)
        XCTAssertEqual(decrypted, plaintext)
    }

    /// Mirrors the requestStream cap in Client.swift: a length prefix larger than
    /// the maximum chunk size must be rejected before buffering the chunk body.
    func testStreamingRejectsOversizedChunkLength() throws {
        // Length prefix declaring a ~4 GiB chunk (0xFFFFFFFF).
        var buffer: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF]

        func parseFramedChunks() throws {
            while buffer.count >= 4 {
                let chunkLength = Int(buffer[0]) << 24 |
                                  Int(buffer[1]) << 16 |
                                  Int(buffer[2]) << 8 |
                                  Int(buffer[3])

                if chunkLength == 0 {
                    buffer.removeFirst(4)
                    continue
                }

                if chunkLength > EHBPConstants.maxResponseChunkBytes {
                    throw EHBPError.invalidResponse("response chunk exceeds maximum allowed size")
                }

                guard buffer.count >= 4 + chunkLength else {
                    break
                }
                buffer.removeFirst(4 + chunkLength)
            }
        }

        XCTAssertThrowsError(try parseFramedChunks()) { error in
            guard case EHBPError.invalidResponse = error else {
                return XCTFail("expected invalidResponse, got \(error)")
            }
        }
    }

    func testTokenDecryptorDeliversBeforeEOFAndHandlesFramingPatterns() throws {
        let token = SessionRecoveryToken(
            exportedSecret: Data(repeating: 0xAB, count: EHBPConstants.exportLength),
            requestEnc: Data(repeating: 0xCD, count: EHBPConstants.requestEncLength)
        )
        let responseNonce = Data(
            repeating: 0xEF,
            count: EHBPConstants.responseNonceLength
        )
        let keyMaterial = try deriveResponseKeys(
            exportedSecret: token.exportedSecret,
            requestEnc: token.requestEnc,
            responseNonce: responseNonce
        )
        let first = try framedChunk(
            keyMaterial: keyMaterial,
            sequence: 0,
            plaintext: Data("first".utf8)
        )
        let second = try framedChunk(
            keyMaterial: keyMaterial,
            sequence: 1,
            plaintext: Data("second".utf8)
        )
        var decryptor = try token.makeResponseDecryptor(responseNonce: responseNonce)

        XCTAssertTrue(try decryptor.push(first.prefix(3)).isEmpty)
        XCTAssertEqual(try decryptor.push(first.dropFirst(3)), [Data("first".utf8)])

        var coalesced = Data(repeating: 0, count: 4)
        coalesced.append(second)
        coalesced.append(Data(repeating: 0, count: 4))
        XCTAssertEqual(try decryptor.push(coalesced), [Data("second".utf8)])
        try decryptor.finish()
    }

    func testTokenDecryptorRejectsTruncationAndAuthenticationFailure() throws {
        let token = SessionRecoveryToken(
            exportedSecret: Data(repeating: 0xAB, count: EHBPConstants.exportLength),
            requestEnc: Data(repeating: 0xCD, count: EHBPConstants.requestEncLength)
        )
        let responseNonce = Data(
            repeating: 0xEF,
            count: EHBPConstants.responseNonceLength
        )
        let keyMaterial = try deriveResponseKeys(
            exportedSecret: token.exportedSecret,
            requestEnc: token.requestEnc,
            responseNonce: responseNonce
        )
        let frame = try framedChunk(
            keyMaterial: keyMaterial,
            sequence: 0,
            plaintext: Data("secret".utf8)
        )
        var truncated = try token.makeResponseDecryptor(responseNonce: responseNonce)

        XCTAssertTrue(try truncated.push(frame.dropLast()).isEmpty)
        XCTAssertThrowsError(try truncated.finish())

        var tamperedFrame = frame
        tamperedFrame[tamperedFrame.index(before: tamperedFrame.endIndex)] ^= 1
        var tampered = try token.makeResponseDecryptor(responseNonce: responseNonce)
        XCTAssertThrowsError(try tampered.push(tamperedFrame))
        XCTAssertThrowsError(try tampered.push(Data()))
    }

    func testResponseDecryptorParsesManyCoalescedFrames() throws {
        let keyMaterial = try deriveResponseKeys(
            exportedSecret: Data(repeating: 0xAB, count: EHBPConstants.exportLength),
            requestEnc: Data(repeating: 0xCD, count: EHBPConstants.requestEncLength),
            responseNonce: Data(repeating: 0xEF, count: EHBPConstants.responseNonceLength)
        )
        let chunkCount = 128
        var framedData = Data()
        var plaintexts = [Data]()

        for index in 0..<chunkCount {
            let plaintext = Data("coalesced chunk \(index)".utf8)
            plaintexts.append(plaintext)
            framedData.append(try framedChunk(
                keyMaterial: keyMaterial,
                sequence: UInt64(index),
                plaintext: plaintext
            ))
        }

        var decryptor = ResponseDecryptor(keyMaterial: keyMaterial)
        XCTAssertEqual(try decryptor.push(framedData), plaintexts)
        try decryptor.finish()
    }

    func testResponseDecryptorIngestsIndividualBytes() throws {
        let keyMaterial = try deriveResponseKeys(
            exportedSecret: Data(repeating: 0xAB, count: EHBPConstants.exportLength),
            requestEnc: Data(repeating: 0xCD, count: EHBPConstants.requestEncLength),
            responseNonce: Data(repeating: 0xEF, count: EHBPConstants.responseNonceLength)
        )
        let plaintexts = [
            Data("first byte-fed chunk".utf8),
            Data("second byte-fed chunk".utf8)
        ]
        var framedData = Data(repeating: 0, count: EHBPConstants.responseLengthPrefixBytes)
        for (index, plaintext) in plaintexts.enumerated() {
            framedData.append(try framedChunk(
                keyMaterial: keyMaterial,
                sequence: UInt64(index),
                plaintext: plaintext
            ))
        }

        var decryptor = ResponseDecryptor(keyMaterial: keyMaterial)
        var opened = [Data]()
        for byte in framedData {
            if let plaintext = try decryptor.push(byte) {
                opened.append(plaintext)
            }
        }

        XCTAssertEqual(opened, plaintexts)
        try decryptor.finish()
    }

    func testPullDrivenResponseDecryptorReadsOneFramePerConsumerRequest() async throws {
        let keyMaterial = try deriveResponseKeys(
            exportedSecret: Data(repeating: 0xAB, count: EHBPConstants.exportLength),
            requestEnc: Data(repeating: 0xCD, count: EHBPConstants.requestEncLength),
            responseNonce: Data(repeating: 0xEF, count: EHBPConstants.responseNonceLength)
        )
        let first = try framedChunk(
            keyMaterial: keyMaterial,
            sequence: 0,
            plaintext: Data("first".utf8)
        )
        let second = try framedChunk(
            keyMaterial: keyMaterial,
            sequence: 1,
            plaintext: Data("second".utf8)
        )
        let source = CountingByteSource(bytes: Array(first + second))
        let decryptor = PullDrivenResponseDecryptor(
            iterator: source.makeIterator(),
            decryptor: ResponseDecryptor(keyMaterial: keyMaterial)
        )
        let stream = AsyncThrowingStream<Data, Error>(unfolding: {
            try await decryptor.next()
        })

        XCTAssertEqual(source.bytesRead, 0)
        var iterator = stream.makeAsyncIterator()
        let firstPlaintext = try await iterator.next()
        XCTAssertEqual(firstPlaintext, Data("first".utf8))
        XCTAssertEqual(source.bytesRead, first.count)

        let secondPlaintext = try await iterator.next()
        XCTAssertEqual(secondPlaintext, Data("second".utf8))
        XCTAssertEqual(source.bytesRead, first.count + second.count)

        let end = try await iterator.next()
        XCTAssertNil(end)
        let repeatedEnd = try await iterator.next()
        XCTAssertNil(repeatedEnd)
    }

    func testResponseDecryptorEnforcesSizeAndSequenceLimits() throws {
        let keyMaterial = try deriveResponseKeys(
            exportedSecret: Data(repeating: 0xAB, count: EHBPConstants.exportLength),
            requestEnc: Data(repeating: 0xCD, count: EHBPConstants.requestEncLength),
            responseNonce: Data(repeating: 0xEF, count: EHBPConstants.responseNonceLength)
        )
        var oversized = ResponseDecryptor(keyMaterial: keyMaterial, maxChunkLength: 16)
        XCTAssertThrowsError(try oversized.push(Data([0, 0, 0, 17])))

        var exhausted = ResponseDecryptor(
            keyMaterial: keyMaterial,
            maxChunkLength: EHBPConstants.maxResponseChunkBytes,
            initialSequence: UInt64.max
        )
        var frame = Data([0, 0, 0, 16])
        frame.append(Data(repeating: 0, count: 16))
        XCTAssertThrowsError(try exhausted.push(frame)) { error in
            guard case EHBPError.invalidResponse(let message) = error else {
                return XCTFail("expected invalidResponse, got \(error)")
            }
            XCTAssertTrue(message.contains("sequence overflow"))
        }
    }

    private func framedChunk(
        keyMaterial: ResponseKeyMaterial,
        sequence: UInt64,
        plaintext: Data
    ) throws -> Data {
        let ciphertext = try encryptChunk(
            keyMaterial: keyMaterial,
            seq: sequence,
            plaintext: plaintext
        )
        var length = UInt32(ciphertext.count).bigEndian
        var frame = Data(
            bytes: &length,
            count: EHBPConstants.responseLengthPrefixBytes
        )
        frame.append(ciphertext)
        return frame
    }
}
