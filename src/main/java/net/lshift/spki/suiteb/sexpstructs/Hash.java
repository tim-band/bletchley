package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertible;
import net.lshift.spki.convert.SexpName;

/**
 * SPKI hash value format
 */
public class Hash
    extends PositionBeanConvertible {
    public final String hashType;
    public final byte[] value;

    @SexpName("hash")
    public Hash(
        @P("hashType") String hashType,
        @P("value") byte[] value
    ) {
        super();
        this.hashType = hashType;
        this.value = value;
    }
}
