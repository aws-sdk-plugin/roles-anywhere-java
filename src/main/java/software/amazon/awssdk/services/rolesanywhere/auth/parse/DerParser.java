package software.amazon.awssdk.services.rolesanywhere.auth.parse;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Minimal DER/ASN.1 parser for PBES2 encrypted PKCS#8 structures.
 * Supports SEQUENCE, OCTET STRING, INTEGER, and OID — the types
 * needed to parse PBES2-params (RFC 8018 §A.4).
 */
final class DerParser {

    private static final int CONSTRUCTED = 0x20;

    private final byte[] data;
    private int pos;

    DerParser(byte[] data) {
        this.data = data;
        this.pos = 0;
    }

    boolean hasNext() {
        return pos < data.length;
    }

    Asn1Object readObject() throws IOException {
        if (pos >= data.length) {
            throw new IOException("Unexpected end of DER input");
        }
        int tag = data[pos++] & 0xff;
        int length = readLength();
        if (pos + length > data.length) {
            throw new IOException("DER object length " + length + " exceeds available data at position " + pos);
        }
        byte[] value = new byte[length];
        System.arraycopy(data, pos, value, 0, length);
        pos += length;
        return new Asn1Object(tag, value);
    }

    private int readLength() throws IOException {
        if (pos >= data.length) {
            throw new IOException("Unexpected end of DER input while reading length");
        }
        int b = data[pos++] & 0xff;
        if (b < 0x80) {
            return b;
        }
        int numBytes = b & 0x7f;
        if (numBytes == 0) {
            throw new IOException("Indefinite length encoding is not supported in DER");
        }
        if (numBytes > 4 || pos + numBytes > data.length) {
            throw new IOException("DER length too large or truncated");
        }
        int length = 0;
        for (int i = 0; i < numBytes; i++) {
            length = (length << 8) | (data[pos++] & 0xff);
        }
        if (length < 0) {
            throw new IOException("DER length overflow");
        }
        return length;
    }

    static final class Asn1Object {
        private final int tag;
        private final byte[] value;

        Asn1Object(int tag, byte[] value) {
            this.tag = tag;
            this.value = value;
        }

        byte[] getValue() {
            return value;
        }

        boolean isConstructed() {
            return (tag & CONSTRUCTED) != 0;
        }

        DerParser getParser() {
            return new DerParser(value);
        }

        String getOid() throws IOException {
            if ((tag & 0x1f) != 0x06) {
                throw new IOException("Expected OID, got tag: " + tag);
            }
            if (value.length == 0) {
                throw new IOException("Empty OID value");
            }
            StringBuilder oid = new StringBuilder();
            oid.append(value[0] / 40).append('.').append(value[0] % 40);
            long component = 0;
            for (int i = 1; i < value.length; i++) {
                component = (component << 7) | (value[i] & 0x7f);
                if ((value[i] & 0x80) == 0) {
                    oid.append('.').append(component);
                    component = 0;
                }
            }
            if (value.length > 1 && (value[value.length - 1] & 0x80) != 0) {
                throw new IOException("Truncated OID: unterminated multi-byte component");
            }
            return oid.toString();
        }

        int getInteger() throws IOException {
            try {
                return new BigInteger(value).intValueExact();
            } catch (ArithmeticException e) {
                throw new IOException("ASN.1 INTEGER value does not fit in an int", e);
            }
        }
    }
}
