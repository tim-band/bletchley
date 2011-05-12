package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.DictlikeSexp;
import net.lshift.spki.convert.P;

public class ECDSAPrivateKey
{
    private final ECDSAPublicKey publicKey;
    private final BigInteger d;

    @DictlikeSexp("suiteb-p384-ecdsa-private-key")
    public ECDSAPrivateKey(
        @P("publicKey") ECDSAPublicKey publicKey,
        @P("d") BigInteger d)
    {
        super();
        this.publicKey = publicKey;
        this.d = d;
    }

    public ECDSAPublicKey getPublicKey()
    {
        return publicKey;
    }

    public BigInteger getD()
    {
        return d;
    }
}
