package net.lshift.spki.suiteb;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.StepConverter;
import net.lshift.spki.convert.Convert.StepConverted;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Identifier for a symmetric key, deterministically generated from the key.
 * Symmetrically encrypted packets carry this information so you know what
 * key to decrypt them with.
 */
@StepConverted(AesKeyId.Step.class)
public class AesKeyId {
    public final byte[] keyId;

    public AesKeyId(byte[] keyId) {
        super();
        this.keyId = keyId;
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public boolean equals(Object obj) {
        return EqualsBuilder.reflectionEquals(this, obj);
    }

    public static class Step
        extends StepConverter<AesKeyId, byte[]> {
        @Override
        protected Class<AesKeyId> getResultClass() {
            return AesKeyId.class;
        }

        @Override
        protected Class<byte[]> getStepClass() {
            return byte[].class;
        }

        @Override
        protected byte[] stepIn(AesKeyId o) {
            return o.keyId;
        }

        @Override
        protected AesKeyId stepOut(byte[] s)
            throws ParseException {
            return new AesKeyId(s);
        }
    }
}
