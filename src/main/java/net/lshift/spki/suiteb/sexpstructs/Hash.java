package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

/**
 * SPKI hash value format
 */
public class Hash
    extends PositionBeanConvertable
{
    public final String hashType;
    public final byte[] value;

    @SExpName("hash")
    public Hash(
        @P("hashType") String hashType,
        @P("value") byte[] value)
    {
        super();
        this.hashType = hashType;
        this.value = value;
    }
}
