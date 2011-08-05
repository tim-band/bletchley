package net.lshift.spki.suiteb;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ByteArrayStepConverter;
import net.lshift.spki.convert.Convert.ConvertClass;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Identifier for a symmetric key, deterministically generated from the key.
 * Symmetrically encrypted packets carry this information so you know what
 * key to decrypt them with.
 */
@ConvertClass(AesKeyId.Step.class)
public class AesKeyId {
    public final byte[] keyId;

    public AesKeyId(final byte[] keyId) {
        super();
        this.keyId = keyId;
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public boolean equals(final Object obj) {
        return EqualsBuilder.reflectionEquals(this, obj);
    }

    public static class Step
        extends ByteArrayStepConverter<AesKeyId> {
        @Override
        public Class<AesKeyId> getResultClass() { return AesKeyId.class; }

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
}
