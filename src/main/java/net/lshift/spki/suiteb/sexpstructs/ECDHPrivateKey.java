package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.NameBeanConvertable;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;

public class ECDHPrivateKey extends NameBeanConvertable
{
    private final ECDHPublicKey publicKey;
    private final BigInteger d;

    @SExpName("suiteb-p384-ecdh-private-key")
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
