package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;

import org.bouncycastle.math.ec.ECPoint;

public class ECDSAPublicKey extends ECPublicKey
{
    @SExpName("suiteb-p384-ecdsa-public-key")
    public ECDSAPublicKey(@P("point") ECPoint point)
    {
        super(point);
    }
}
