package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

public class ECDHPublicKey  extends PositionBeanConvertable
{
    private final Point point;

    @SExpName("suiteb-p384-ecdh-public-key")
    public ECDHPublicKey(@P("point") Point point)
    {
        super();
        this.point = point;
    }

    public Point getPoint()
    {
        return point;
    }
}
