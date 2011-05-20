package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.NameBeanConvertible;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SexpName;
import net.lshift.spki.convert.StepConverter;
import net.lshift.spki.suiteb.Ec;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for an ECPoint ie a point on an elliptic curve.
 */
public class Point extends NameBeanConvertible
{
    public final BigInteger x;
    public final BigInteger y;

    @SexpName("point")
    public Point(
        @P("x") BigInteger x,
        @P("y") BigInteger y
    ) {
        super();
        this.x = x;
        this.y = y;
    }

    public static class ECPointConverter
        extends StepConverter<ECPoint, Point>
    {
        public ECPointConverter() { super(); }

        @Override
        public Class<Point> getStepClass() { return Point.class; }

        @Override
        public Class<ECPoint> getResultClass() { return ECPoint.class; }

        @Override
        public Point stepIn(ECPoint q)
        {
            return new Point(
                q.getX().toBigInteger(), q.getY().toBigInteger());
        }

        @Override
        public ECPoint stepOut(Point point)
        {
            return Ec.DOMAIN_PARAMETERS.getCurve().createPoint(
                point.x, point.y, false);
        }
    }

    static {
        new ECPointConverter().registerSelf();
    }

    public static void ensureRegistered() {
        // Do nothing - just ensures the class is loaded and so registered
    }
}
