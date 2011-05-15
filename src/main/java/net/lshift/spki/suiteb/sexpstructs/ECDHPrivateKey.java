package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;

public class ECDHPrivateKey extends ECPrivateKey
{
    @SExpName("suiteb-p384-ecdh-private-key")
    public ECDHPrivateKey(
        @P("publicKey") ECDHPublicKey publicKey,
        @P("d") BigInteger d)
    {
        super(publicKey, d);
    }
}
