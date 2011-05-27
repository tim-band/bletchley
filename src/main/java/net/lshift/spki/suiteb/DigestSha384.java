package net.lshift.spki.suiteb;

import java.io.IOException;
import java.util.Arrays;

import net.lshift.spki.convert.ConvertException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.PackConvertible;
import net.lshift.spki.suiteb.sexpstructs.Hash;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.util.encoders.Hex;

/**
 * A SHA-384 digest of a SExp.
 */
public class DigestSha384
    extends PackConvertible {
    private static final String DIGEST_NAME = "sha384";
    private final int DIGEST_LENGTH = 48;
    private final byte[] bytes;

    public DigestSha384(byte[] bytes) {
        super();
        if (bytes.length != DIGEST_LENGTH) {
            throw new RuntimeException("Wrong number of bytes, expected"
                + DIGEST_LENGTH + ", got " + bytes.length);
        }
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public Hash pack() {
        return new Hash(DIGEST_NAME, bytes);
    }

    public static DigestSha384 unpack(Hash hash) {
        if (!DIGEST_NAME.equals(hash.hashType)) {
            throw new ConvertException("Unexpected hash type: " + hash.hashType);
        }
        return new DigestSha384(hash.value);
    }

    public static <T> DigestSha384 digest(Class<T> clazz, T o) {
        SHA384Digest sha = new SHA384Digest();
        DigestOutputStream digester = new DigestOutputStream(
            new DevnullOutputStream(), sha);
        try {
            ConvertUtils.write(clazz, o, digester);
        } catch (IOException e) {
            throw new AssertionError("CANTHAPPEN:" + e);
        }
        byte[] digest = new byte[sha.getDigestSize()];
        sha.doFinal(digest, 0);
        return new DigestSha384(digest);
    }

    public static DigestSha384 digest(SequenceItem item) {
        return digest(SequenceItem.class, item);
    }

    @Override
    public String toString() {
        return "DigestSha384 [bytes=" + new String(Hex.encode(bytes)) + "]";
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        DigestSha384 other = (DigestSha384) obj;
        if (!Arrays.equals(bytes, other.bytes)) return false;
        return true;
    }
}
