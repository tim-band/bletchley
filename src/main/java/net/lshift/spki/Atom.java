package net.lshift.spki;

import java.util.Arrays;

/**
 * An atom in an SPKI S-expression
 */
public final class Atom implements SExp {
    private final byte[] bytes;

    public Atom(byte[] bytes) {
        super();
        assert bytes != null;
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(bytes);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Atom other = (Atom) obj;
        if (!Arrays.equals(bytes, other.bytes))
            return false;
        return true;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for (byte b: bytes) {
            if (Character.isLetterOrDigit(b) || b == (byte) '-') {
                sb.append((char) b);
            } else {
                sb.append(String.format("\\0x%02x", b));
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
