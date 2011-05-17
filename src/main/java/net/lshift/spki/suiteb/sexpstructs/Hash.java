package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

public class Hash
    extends PositionBeanConvertable
{
    private final String hashType;
    private final byte[] value;

    @SExpName("hash")
    public Hash(
        @P("hashType") String hashType,
        @P("value") byte[] value)
    {
        super();
        this.hashType = hashType;
        this.value = value;
    }

    public String getHashType()
    {
        return hashType;
    }

    public byte[] getValue()
    {
        return value;
    }
}
