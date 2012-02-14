package net.lshift.spki.suiteb;

import java.io.IOException;
import java.util.Arrays;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.suiteb.sexpstructs.Hash;

import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.util.encoders.Hex;

/**
 * A SHA-384 digest of a SExp.
 */
@ConvertClass(DigestSha384.Step.class)
public class DigestSha384 implements SequenceItem {
    public static final String DIGEST_NAME = "sha384";
    private static final int DIGEST_LENGTH = 48;
    private final byte[] bytes;

    protected DigestSha384(final byte[] bytes) {
        super();
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public static <T> DigestSha384 digest(final Class<T> clazz, final T o) {
        final SHA384Digest sha = new SHA384Digest();
        final DigestOutputStream digester = new DigestOutputStream(
            new DevnullOutputStream(), sha);
        try {
            ConvertUtils.write(clazz, o, digester);
        } catch (final IOException e) {
            throw new AssertionError("CANTHAPPEN:" + e);
        }
        final byte[] digest = new byte[sha.getDigestSize()];
        sha.doFinal(digest, 0);
        return new DigestSha384(digest);
    }

    public static DigestSha384 digest(final SequenceItem item) {
        return digest(SequenceItem.class, item);
    }

    public static class Step
        extends ListStepConverter<DigestSha384, Hash> {

        @Override
        public Class<DigestSha384> getResultClass() {
            return DigestSha384.class;
        }

        @Override
        protected Class<Hash> getStepClass() {
            return Hash.class;
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected Hash stepIn(final DigestSha384 o) {
            return new Hash(DIGEST_NAME, o.bytes);
        }

        @Override
        protected DigestSha384 stepOut(final Hash hash)
            throws InvalidInputException {
            if (!DIGEST_NAME.equals(hash.hashType)) {
                throw new CryptographyException(
                    "Unexpected hash type: " + hash.hashType);
            }
            final byte[] bytes = hash.value;
            if (bytes.length != DIGEST_LENGTH) {
                throw new CryptographyException(
                    "Wrong number of bytes, expected"
                    + DIGEST_LENGTH + ", got " + bytes.length);
            }
            return new DigestSha384(bytes);
        }
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
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        final DigestSha384 other = (DigestSha384) obj;
        if (!Arrays.equals(bytes, other.bytes)) return false;
        return true;
    }

    @Override
    public void process(InferenceEngine engine, Condition trust)
        throws InvalidInputException {
        engine.addItemTrust(this, trust);
    }
}
