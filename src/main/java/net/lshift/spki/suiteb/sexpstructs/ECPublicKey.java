package net.lshift.spki.suiteb.sexpstructs;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.suiteb.EC;

public class ECPublicKey
    extends PositionBeanConvertable
{
    protected final ECPoint point;

    public ECPublicKey(ECPoint point)
    {
        this.point = point;
    }

    public ECPoint getPoint()
    {
        return point;
    }

    public ECPublicKeyParameters getParameters()
    {
        return EC.toECPublicKeyParameters(point);
    }

    static {
        Point.ensureRegistered();
    }
}
