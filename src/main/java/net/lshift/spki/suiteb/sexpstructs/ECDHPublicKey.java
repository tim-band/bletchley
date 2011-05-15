package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;

import org.bouncycastle.math.ec.ECPoint;

public class ECDHPublicKey extends ECPublicKey
{
    @SExpName("suiteb-p384-ecdh-public-key")
    public ECDHPublicKey(@P("point") ECPoint point)
    {
        super(point);
    }
}
