package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.ConvertException;
import net.lshift.spki.convert.StepConverter;
import net.lshift.spki.suiteb.Ec;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class ECPointConverter
    extends StepConverter<ECPoint, ECPointConverter.Point> {

    /**
     * Serialization format for an ECPoint ie a point on an elliptic curve.
     */
    @Convert.ByName("point")
    public static class Point {
        public final BigInteger x;
        public final BigInteger y;

        public Point(
            final BigInteger x,
            final BigInteger y
        ) {
            super();
            this.x = x;
            this.y = y;
        }
    }

    public ECPointConverter() { super(); }

    @Override
    public Class<Point> getStepClass() { return Point.class; }

    @Override
    public Class<ECPoint> getResultClass() { return ECPoint.class; }

    @Override
    public ECPointConverter.Point stepIn(final ECPoint q) {
        return new Point(
            q.getX().toBigInteger(), q.getY().toBigInteger());
    }

    @Override
    public ECPoint stepOut(final Point point) throws ConvertException {
        final ECCurve curve = Ec.DOMAIN_PARAMETERS.getCurve();
        final ECPoint res = curve.createPoint(
            point.x, point.y, false);
        final ECFieldElement x = res.getX();
        if (!res.getY().square().equals(
            x.multiply(x.square().add(curve.getA())).add(curve.getB()))) {
            throw new ConvertException("Point is not on curve");
        }
        return res;
    }
}
