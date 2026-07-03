// Minimal Noise NK implementation for EHBP-WS (SPEC Section 8).
//
// Implements exactly the Noise_NK_25519_AESGCM_SHA256 handshake and the raw
// AES-256-GCM transport cipher states, following the Noise Protocol
// Framework revision 34. The record layer runs on raw cipher states because
// EHBP-WS records may exceed the Noise transport message cap of 65535 bytes.

import Crypto
import Foundation

private let noiseHashLength = 32
private let noiseKeyLength = 32
private let noiseTagLength = 16
private let noiseDHLength = 32
private let noiseMaxNonce = UInt64.max

/// The Noise AEAD nonce: 4 zero bytes followed by a big-endian counter.
private func noiseNonce(_ counter: UInt64) -> Data {
    var nonce = Data(repeating: 0, count: 4)
    withUnsafeBytes(of: counter.bigEndian) { nonce.append(contentsOf: $0) }
    return nonce
}

private func aeadSeal(key: Data, counter: UInt64, authenticating ad: Data, plaintext: Data) throws -> Data {
    let sealed = try AES.GCM.seal(
        plaintext,
        using: SymmetricKey(data: key),
        nonce: AES.GCM.Nonce(data: noiseNonce(counter)),
        authenticating: ad
    )
    // Rebase to zero-based indices: SealedBox properties are slices.
    var out = Data(sealed.ciphertext)
    out.append(sealed.tag)
    return out
}

private func aeadOpen(key: Data, counter: UInt64, authenticating ad: Data, ciphertext: Data) throws -> Data {
    guard ciphertext.count >= noiseTagLength else {
        throw EHBPError.decryptionFailed("ciphertext shorter than AEAD tag")
    }
    let box = try AES.GCM.SealedBox(
        nonce: AES.GCM.Nonce(data: noiseNonce(counter)),
        ciphertext: Data(ciphertext.dropLast(noiseTagLength)),
        tag: Data(ciphertext.suffix(noiseTagLength))
    )
    return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: ad)
}

/// HKDF as defined by the Noise specification Section 4.3 (two outputs).
private func noiseHKDF(chainingKey: Data, input: Data) -> (Data, Data) {
    let tempKey = SymmetricKey(data: Data(HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: chainingKey))))
    let output1 = Data(HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: tempKey))
    let output2 = Data(HMAC<SHA256>.authenticationCode(for: output1 + Data([0x02]), using: tempKey))
    return (output1, output2)
}

/// One direction of the transport: an AES-256-GCM cipher with the Noise
/// implicit nonce and the deterministic rekey schedule of SPEC Section 8.6.
struct NoiseRecordCipher {
    private var key: Data
    private var count: UInt64
    private let rekeyInterval: UInt64

    init(key: Data, rekeyInterval: UInt64) {
        self.key = key
        self.count = 0
        self.rekeyInterval = rekeyInterval
    }

    mutating func encrypt(_ plaintext: Data) throws -> Data {
        let ciphertext = try aeadSeal(key: key, counter: count, authenticating: Data(), plaintext: plaintext)
        try advance()
        return ciphertext
    }

    mutating func decrypt(_ ciphertext: Data) throws -> Data {
        let plaintext: Data
        do {
            plaintext = try aeadOpen(key: key, counter: count, authenticating: Data(), ciphertext: ciphertext)
        } catch {
            throw EHBPError.decryptionFailed("failed to decrypt record")
        }
        try advance()
        return plaintext
    }

    private mutating func advance() throws {
        guard count < noiseMaxNonce else {
            throw EHBPError.encryptionFailed("record counter exhausted")
        }
        count += 1
        if count % rekeyInterval == 0 {
            try rekey()
        }
    }

    /// Rekey per Noise spec Section 4.2: the new key is the encryption of
    /// 32 zero bytes under the maximum nonce, with the tag discarded. The
    /// nonce counter deliberately keeps running.
    private mutating func rekey() throws {
        let block = try aeadSeal(
            key: key,
            counter: noiseMaxNonce,
            authenticating: Data(),
            plaintext: Data(repeating: 0, count: noiseKeyLength)
        )
        key = Data(block.prefix(noiseKeyLength))
    }
}

enum NoiseRole {
    case initiator
    case responder
}

struct NoiseSymmetricState {
    private(set) var chainingKey: Data
    private(set) var hash: Data
    private var key: Data?
    private var counter: UInt64 = 0

    init(protocolName: String) {
        let name = Data(protocolName.utf8)
        if name.count <= noiseHashLength {
            hash = name + Data(repeating: 0, count: noiseHashLength - name.count)
        } else {
            hash = Data(SHA256.hash(data: name))
        }
        chainingKey = hash
    }

    mutating func mixHash(_ data: Data) {
        hash = Data(SHA256.hash(data: hash + data))
    }

    mutating func mixKey(_ input: Data) {
        let (newChainingKey, newKey) = noiseHKDF(chainingKey: chainingKey, input: input)
        chainingKey = newChainingKey
        key = newKey
        counter = 0
    }

    mutating func encryptAndHash(_ plaintext: Data) throws -> Data {
        guard let key else {
            mixHash(plaintext)
            return plaintext
        }
        let ciphertext = try aeadSeal(key: key, counter: counter, authenticating: hash, plaintext: plaintext)
        counter += 1
        mixHash(ciphertext)
        return ciphertext
    }

    mutating func decryptAndHash(_ ciphertext: Data) throws -> Data {
        guard let key else {
            mixHash(ciphertext)
            return ciphertext
        }
        let plaintext = try aeadOpen(key: key, counter: counter, authenticating: hash, ciphertext: ciphertext)
        counter += 1
        mixHash(ciphertext)
        return plaintext
    }

    /// Returns the two transport keys, initiator-to-responder first.
    func split() -> (Data, Data) {
        noiseHKDF(chainingKey: chainingKey, input: Data())
    }
}

/// The Noise NK handshake:
///
///     NK:
///       <- s
///       ...
///       -> e, es
///       <- e, ee
struct NoiseHandshakeState {
    private var symmetric: NoiseSymmetricState
    let role: NoiseRole
    private let localEphemeral: Curve25519.KeyAgreement.PrivateKey
    private let localStatic: Curve25519.KeyAgreement.PrivateKey?
    private let remoteStatic: Data?
    private var remoteEphemeral: Data?

    var handshakeHash: Data { symmetric.hash }

    init(
        role: NoiseRole,
        prologue: Data,
        remoteStaticKey: Data? = nil,
        localStaticKey: Curve25519.KeyAgreement.PrivateKey? = nil,
        ephemeral: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey()
    ) throws {
        symmetric = NoiseSymmetricState(protocolName: NoiseWebSocketProtocol.protocolName)
        symmetric.mixHash(prologue)
        // NK pre-message pattern: the responder's static key.
        switch role {
        case .initiator:
            guard let remoteStaticKey, remoteStaticKey.count == noiseDHLength else {
                throw EHBPError.handshakeFailed("server static key must be \(noiseDHLength) bytes")
            }
            symmetric.mixHash(remoteStaticKey)
        case .responder:
            guard let localStaticKey else {
                throw EHBPError.handshakeFailed("responder requires a static key")
            }
            symmetric.mixHash(localStaticKey.publicKey.rawRepresentation)
        }
        self.role = role
        self.localEphemeral = ephemeral
        self.localStatic = localStaticKey
        self.remoteStatic = remoteStaticKey
    }

    private mutating func mixDH(
        _ privateKey: Curve25519.KeyAgreement.PrivateKey, _ publicKeyBytes: Data
    ) throws {
        let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyBytes)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        symmetric.mixKey(shared.withUnsafeBytes { Data($0) })
    }

    /// Initiator: "-> e, es"
    mutating func writeMessage1(payload: Data = Data()) throws -> Data {
        guard role == .initiator, let remoteStatic else {
            throw EHBPError.handshakeFailed("writeMessage1 requires the initiator role")
        }
        let ephemeralPublic = localEphemeral.publicKey.rawRepresentation
        symmetric.mixHash(ephemeralPublic)
        try mixDH(localEphemeral, remoteStatic)
        return ephemeralPublic + (try symmetric.encryptAndHash(payload))
    }

    /// Responder: "-> e, es"
    mutating func readMessage1(_ message: Data) throws -> Data {
        guard role == .responder, let localStatic else {
            throw EHBPError.handshakeFailed("readMessage1 requires the responder role")
        }
        guard message.count >= noiseDHLength + noiseTagLength else {
            throw EHBPError.handshakeFailed("handshake message too short")
        }
        let ephemeral = Data(message.prefix(noiseDHLength))
        remoteEphemeral = ephemeral
        symmetric.mixHash(ephemeral)
        try mixDH(localStatic, ephemeral)
        do {
            return try symmetric.decryptAndHash(Data(message.dropFirst(noiseDHLength)))
        } catch {
            throw EHBPError.handshakeFailed("handshake message failed authentication")
        }
    }

    /// Responder: "<- e, ee"
    mutating func writeMessage2(payload: Data = Data()) throws -> Data {
        guard role == .responder, let remoteEphemeral else {
            throw EHBPError.handshakeFailed("writeMessage2 requires readMessage1 first")
        }
        let ephemeralPublic = localEphemeral.publicKey.rawRepresentation
        symmetric.mixHash(ephemeralPublic)
        try mixDH(localEphemeral, remoteEphemeral)
        return ephemeralPublic + (try symmetric.encryptAndHash(payload))
    }

    /// Initiator: "<- e, ee"
    mutating func readMessage2(_ message: Data) throws -> Data {
        guard role == .initiator else {
            throw EHBPError.handshakeFailed("readMessage2 requires the initiator role")
        }
        guard message.count >= noiseDHLength + noiseTagLength else {
            throw EHBPError.handshakeFailed("handshake message too short")
        }
        let ephemeral = Data(message.prefix(noiseDHLength))
        remoteEphemeral = ephemeral
        symmetric.mixHash(ephemeral)
        try mixDH(localEphemeral, ephemeral)
        do {
            return try symmetric.decryptAndHash(Data(message.dropFirst(noiseDHLength)))
        } catch {
            throw EHBPError.handshakeFailed("handshake message failed authentication")
        }
    }

    /// Returns the two transport keys, initiator-to-responder first.
    func split() -> (Data, Data) {
        symmetric.split()
    }
}
