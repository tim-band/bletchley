package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.NameBeanConvertable;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;

/**
 * Serialization format for a raw ECDSA signature
 */
public class ECDSASignature extends NameBeanConvertable
{
    public final BigInteger r;
    public final BigInteger s;

    @SExpName("suiteb-p384-ecdsa-signature")
    public ECDSASignature(
        @P("r") BigInteger r,
        @P("s") BigInteger s
    ) {
        super();
        this.r = r;
        this.s = s;
    }
}
