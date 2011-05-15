package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.NameBeanConvertable;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;

public class ECDSASignature extends NameBeanConvertable
{
    private final BigInteger r;
    private final BigInteger s;

    @SExpName("suiteb-p384-ecdsa-signature")
    public ECDSASignature(
        @P("r") BigInteger r,
        @P("s") BigInteger s
    ) {
        super();
        this.r = r;
        this.s = s;
    }

    public BigInteger getR()
    {
        return r;
    }
    public BigInteger getS()
    {
        return s;
    }
}
