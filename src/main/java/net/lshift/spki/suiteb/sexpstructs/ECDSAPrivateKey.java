package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;

public class ECDSAPrivateKey  extends ECPrivateKey
{
    @SExpName("suiteb-p384-ecdsa-private-key")
    public ECDSAPrivateKey(
        @P("publicKey") ECDSAPublicKey publicKey,
        @P("d") BigInteger d)
    {
        super(publicKey, d);
    }
}
