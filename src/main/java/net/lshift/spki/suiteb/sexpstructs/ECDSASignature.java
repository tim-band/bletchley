package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.DictlikeSexp;
import net.lshift.spki.convert.P;

public class ECDSASignature
{
    private final BigInteger r;
    private final BigInteger s;

    @DictlikeSexp("suiteb-p384-ecdsa-signature")
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
