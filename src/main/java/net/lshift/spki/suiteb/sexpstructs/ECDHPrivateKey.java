package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.DictlikeSexp;
import net.lshift.spki.convert.P;

public class ECDHPrivateKey
{
    private final ECDHPublicKey publicKey;
    private final BigInteger d;

    @DictlikeSexp("suiteb-p384-ecdh-private-key")
    public ECDHPrivateKey(
        @P("publicKey") ECDHPublicKey publicKey,
        @P("d") BigInteger d)
    {
        super();
        this.publicKey = publicKey;
        this.d = d;
    }

    public ECDHPublicKey getPublicKey()
    {
        return publicKey;
    }

    public BigInteger getD()
    {
        return d;
    }
}
