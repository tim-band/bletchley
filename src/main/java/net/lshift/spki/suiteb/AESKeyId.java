package net.lshift.spki.suiteb;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

import net.lshift.spki.convert.PackConvertible;

/**
 * Identifier for a symmetric key, deterministically generated from the key.
 * Symmetrically encrypted packets carry this information so you know what
 * key to decrypt them with.
 */
public class AESKeyId extends PackConvertible
{
    public final byte[] keyId;

    public AESKeyId(byte[] keyId)
    {
        super();
        this.keyId = keyId;
    }

    @Override
    public byte[] pack() {
        return keyId;
    }

    public static AESKeyId unpack(byte[] keyId) {
        return new AESKeyId(keyId);
    }
    @Override
    public int hashCode()
    {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public boolean equals(Object obj)
    {
        return EqualsBuilder.reflectionEquals(this, obj);
    }
}
