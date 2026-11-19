package sh.tinfoil.ehbp.identity;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import okio.Buffer;
import okio.BufferedSink;
import okio.ByteString;
import okio.ForwardingSink;
import okio.Okio;
import okio.Source;
import okio.Timeout;

/**
 * Okio's buffered sink copies a whole array or string into its buffer before emitting segments.
 * Split producer writes before they reach that buffer. Fluent methods return this view so
 * chained writes keep the same bound. A producer that explicitly fills buffer() owns those bytes.
 */
final class ChunkedRequestSink implements BufferedSink {
    private final BufferedSink sink;
    private final int chunkSize;

    ChunkedRequestSink(OutputStream writer, int chunkSize) {
        this.chunkSize = chunkSize;
        // Closing the plaintext sink finishes buffered writes. OkHttp owns the network sink.
        this.sink = Okio.buffer(new ForwardingSink(Okio.sink(writer)) {
            @Override public void close() throws IOException { flush(); }
        });
    }

    private static void checkRange(int size, int offset, int count) {
        if (offset < 0 || count < 0 || offset > size - count) {
            throw new IndexOutOfBoundsException("offset=" + offset + ", count=" + count + ", size=" + size);
        }
    }

    @Override public BufferedSink write(byte[] source) throws IOException {
        return write(source, 0, source.length);
    }

    @Override public BufferedSink write(byte[] source, int offset, int count) throws IOException {
        checkRange(source.length, offset, count);
        int end = offset + count;
        while (offset < end) {
            int n = Math.min(end - offset, chunkSize);
            sink.write(source, offset, n);
            offset += n;
        }
        return this;
    }

    @Override public BufferedSink write(ByteString bytes) throws IOException {
        return write(bytes, 0, bytes.size());
    }

    @Override public BufferedSink write(ByteString bytes, int offset, int count) throws IOException {
        checkRange(bytes.size(), offset, count);
        int end = offset + count;
        while (offset < end) {
            int n = Math.min(end - offset, chunkSize);
            sink.write(bytes, offset, n);
            offset += n;
        }
        return this;
    }

    @Override public int write(ByteBuffer source) throws IOException {
        int count = source.remaining();
        if (source.hasArray()) {
            write(source.array(), source.arrayOffset() + source.position(), count);
            ((java.nio.Buffer) source).position(source.limit());
        } else {
            byte[] block = new byte[Math.min(count, chunkSize)];
            while (source.hasRemaining()) {
                int n = Math.min(source.remaining(), block.length);
                source.get(block, 0, n);
                sink.write(block, 0, n);
            }
        }
        return count;
    }

    @Override public void write(Buffer source, long count) throws IOException {
        if (count < 0 || count > source.size()) throw new IndexOutOfBoundsException("byteCount=" + count);
        while (count > 0) {
            long n = Math.min(count, chunkSize);
            sink.write(source, n);
            count -= n;
        }
    }

    @Override public BufferedSink write(Source source, long count) throws IOException {
        if (count < 0) throw new IllegalArgumentException("byteCount=" + count);
        while (count > 0) {
            long n = Math.min(count, chunkSize);
            sink.write(source, n);
            count -= n;
        }
        return this;
    }

    // Okio's writeAll reads one segment per iteration.
    @Override public long writeAll(Source source) throws IOException { return sink.writeAll(source); }

    @Override public BufferedSink writeUtf8(String value) throws IOException {
        return writeUtf8(value, 0, value.length());
    }

    @Override public BufferedSink writeUtf8(String value, int begin, int end) throws IOException {
        checkRange(value.length(), begin, end - begin);
        while (begin < end) {
            int next = begin + Math.min(end - begin, chunkSize);
            if (next < end && Character.isHighSurrogate(value.charAt(next - 1))
                    && Character.isLowSurrogate(value.charAt(next))) next--;
            sink.writeUtf8(value, begin, next);
            begin = next;
        }
        return this;
    }

    @Override public BufferedSink writeString(String value, Charset charset) throws IOException {
        return writeString(value, 0, value.length(), charset);
    }

    @Override public BufferedSink writeString(String value, int begin, int end, Charset charset) throws IOException {
        if (StandardCharsets.UTF_8.equals(charset)) return writeUtf8(value, begin, end);
        checkRange(value.length(), begin, end - begin);
        // Keep one encoder across chunks for surrogate pairs, BOMs, and stateful encodings.
        // Closing it finalizes this string without flushing or closing the request body.
        OutputStream encoded = new OutputStream() {
            @Override public void write(int b) throws IOException { sink.writeByte(b); }
            @Override public void write(byte[] b, int off, int len) throws IOException {
                ChunkedRequestSink.this.write(b, off, len);
            }
        };
        try (OutputStreamWriter encoder = new OutputStreamWriter(encoded, charset)) {
            while (begin < end) {
                int n = Math.min(end - begin, chunkSize);
                encoder.write(value, begin, n);
                begin += n;
            }
        }
        return this;
    }

    @Override public OutputStream outputStream() {
        return new OutputStream() {
            @Override public void write(int b) throws IOException { sink.writeByte(b); }
            @Override public void write(byte[] b, int off, int len) throws IOException {
                ChunkedRequestSink.this.write(b, off, len);
            }
            @Override public void flush() throws IOException { sink.flush(); }
            @Override public void close() throws IOException { sink.close(); }
        };
    }

    @Override public BufferedSink writeUtf8CodePoint(int codePoint) throws IOException { sink.writeUtf8CodePoint(codePoint); return this; }
    @Override public BufferedSink writeByte(int value) throws IOException { sink.writeByte(value); return this; }
    @Override public BufferedSink writeShort(int value) throws IOException { sink.writeShort(value); return this; }
    @Override public BufferedSink writeShortLe(int value) throws IOException { sink.writeShortLe(value); return this; }
    @Override public BufferedSink writeInt(int value) throws IOException { sink.writeInt(value); return this; }
    @Override public BufferedSink writeIntLe(int value) throws IOException { sink.writeIntLe(value); return this; }
    @Override public BufferedSink writeLong(long value) throws IOException { sink.writeLong(value); return this; }
    @Override public BufferedSink writeLongLe(long value) throws IOException { sink.writeLongLe(value); return this; }
    @Override public BufferedSink writeDecimalLong(long value) throws IOException { sink.writeDecimalLong(value); return this; }
    @Override public BufferedSink writeHexadecimalUnsignedLong(long value) throws IOException { sink.writeHexadecimalUnsignedLong(value); return this; }
    @Override public BufferedSink emit() throws IOException { sink.emit(); return this; }
    @Override public BufferedSink emitCompleteSegments() throws IOException { sink.emitCompleteSegments(); return this; }
    @Override public Buffer getBuffer() { return sink.getBuffer(); }
    @Deprecated @Override public Buffer buffer() { return getBuffer(); }
    @Override public Timeout timeout() { return sink.timeout(); }
    @Override public boolean isOpen() { return sink.isOpen(); }
    @Override public void flush() throws IOException { sink.flush(); }
    @Override public void close() throws IOException { sink.close(); }
}
