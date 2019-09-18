package net.lshift.spki.suiteb;

import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.util.encoders.Hex;

import com.google.protobuf.ByteString;
import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.ProtobufConvertible;

/**
 * A SHA-384 digest of a SExp.
 */
public class DigestSha384 implements SequenceItem {
    public static final String DIGEST_NAME = "sha384";
    public static final int DIGEST_LENGTH = 48;
    private final byte[] bytes;

    public DigestSha384(final byte[] bytes) {
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public static DigestSha384 digest(final SequenceItem o) {
        final SHA384Digest sha = new SHA384Digest();
        final DigestOutputStream digester = new DigestOutputStream(sha);
        try {
            ConvertUtils.write(o, digester);
            digester.close();
        } catch (final IOException e) {
            throw new AssertionError("CANTHAPPEN:" + e);
        }
        final byte[] digest = new byte[sha.getDigestSize()];
        sha.doFinal(digest, 0);
        return new DigestSha384(digest);
    }

    /**
     * Convert an object to a protocol buffer, and then digests it.
     * It will digest anything that can be converted to a protocol
     * buffer, but returns bytes, because a Digest384 is a digest
     * of a SequenceItem. This method is defined here only because
     * of the code it has in common.
     * @param o the object to generate a digest for.
     * @return the digest
     */
    public static byte [] digest(ProtobufConvertible<?> o) {
        final SHA384Digest sha = new SHA384Digest();
        final DigestOutputStream digester = new DigestOutputStream(sha);
        try {
            o.toProtobuf().build().writeTo(digester);
            final byte[] digest = new byte[sha.getDigestSize()];
            sha.doFinal(digest, 0);
            return digest;
        } catch (IOException e) {
            throw new AssertionError("CANTHAPPEN:" + e);
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
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        engine.addItemTrust(this, trust);
    }

    public SuiteBProto.Hash.Builder toProtobufHash() {
        return SuiteBProto.Hash.newBuilder()
                .setType(DIGEST_NAME)
                .setValue(ByteString.copyFrom(bytes));
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobuf() {
        return SuiteBProto.SequenceItem.newBuilder().setHash(this.toProtobufHash());
    }
}
