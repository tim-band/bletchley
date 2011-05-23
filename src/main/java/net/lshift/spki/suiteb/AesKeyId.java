package net.lshift.spki.suiteb;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

import net.lshift.spki.convert.PackConvertible;

/**
 * Identifier for a symmetric key, deterministically generated from the key.
 * Symmetrically encrypted packets carry this information so you know what
 * key to decrypt them with.
 */
public class AesKeyId
    extends PackConvertible {
    public final byte[] keyId;

    public AesKeyId(byte[] keyId) {
        super();
        this.keyId = keyId;
    }

    @Override
    public byte[] pack() {
        return keyId;
    }

    public static AesKeyId unpack(byte[] keyId) {
        return new AesKeyId(keyId);
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public boolean equals(Object obj) {
        return EqualsBuilder.reflectionEquals(this, obj);
    }
}
