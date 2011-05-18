package net.lshift.spki.suiteb;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

import net.lshift.spki.convert.PackConvertable;

public class AESKeyId extends PackConvertable
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
