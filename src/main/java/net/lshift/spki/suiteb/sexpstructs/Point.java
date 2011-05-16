package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.NameBeanConvertable;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.convert.StepConverter;
import net.lshift.spki.suiteb.EC;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for an ECPoint ie a point on an elliptic curve.
 */
public class Point extends NameBeanConvertable
{
    private final BigInteger x;
    private final BigInteger y;

    @SExpName("point")
    public Point(
        @P("x") BigInteger x,
        @P("y") BigInteger y
    ) {
        super();
        this.x = x;
        this.y = y;
    }

    public BigInteger getX()
    {
        return x;
    }

    public BigInteger getY()
    {
        return y;
    }

    private static class ECPointConverter
        extends StepConverter<ECPoint, Point>
    {
        @Override
        protected Class<Point> getStepClass() { return Point.class; }

        @Override
        protected Class<ECPoint> getResultClass() { return ECPoint.class; }

        @Override
        protected Point stepIn(ECPoint q)
        {
            return new Point(
                q.getX().toBigInteger(), q.getY().toBigInteger());
        }

        @Override
        protected ECPoint stepOut(Point point)
        {
            return EC.DOMAIN_PARAMETERS.getCurve().createPoint(
                point.getX(), point.getY(), false);
        }
    }

    static {
        new ECPointConverter().registerSelf();
    }

    public static void ensureRegistered() {
        // Do nothing - just ensures the class is loaded and so registered
    }
}
