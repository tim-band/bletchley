package net.lshift.spki.suiteb;

import java.util.Arrays;

import com.google.protobuf.ByteString;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ByteArrayStepConverter;
import net.lshift.spki.convert.Convert.ConvertClass;

/**
 * Identifier for a symmetric key, deterministically generated from the key.
 * Symmetrically encrypted packets carry this information so you know what
 * key to decrypt them with.
 */
@ConvertClass(AesKeyId.Step.class)
public final class AesKeyId {
    public final byte[] keyId;

    public AesKeyId(final byte[] keyId) {
        this.keyId = keyId;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyId);
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        return Arrays.equals(keyId, ((AesKeyId) obj).keyId);
    }

    public static class Step
        extends ByteArrayStepConverter<AesKeyId> {
        public Step() { super(AesKeyId.class); }

        @Override
        protected byte[] stepIn(final AesKeyId o) {
            return o.keyId;
        }

        @Override
        protected AesKeyId stepOut(final byte[] s)
            throws ParseException {
            return new AesKeyId(s);
        }
    }

    public ByteString toProtobuf() {
        return ByteString.copyFrom(keyId);
    }
}
