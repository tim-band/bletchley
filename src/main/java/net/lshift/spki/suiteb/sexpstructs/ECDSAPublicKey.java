package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionalSexp;

public class ECDSAPublicKey
{
    private final Point point;

    @PositionalSexp("suiteb-p384-ecdsa-public-key")
    public ECDSAPublicKey(@P("point") Point point)
    {
        super();
        this.point = point;
    }

    public Point getPoint()
    {
        return point;
    }
}
