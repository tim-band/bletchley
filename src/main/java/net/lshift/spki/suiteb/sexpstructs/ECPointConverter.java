package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.suiteb.CryptographyException;
import net.lshift.spki.suiteb.Ec;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Foreign converter for the ECPoint class - converts to our
 * Point representation.
 */
public class ECPointConverter
        extends ListStepConverter<ECPoint, ECPointConverter.Point> {

    /**
     * Serialization format for an ECPoint ie a point on an elliptic curve.
     */
    @Convert.ByName("point")
    public static class Point {
        public final BigInteger x;
        public final BigInteger y;

        public Point(final BigInteger x, final BigInteger y) {
            this.x = x;
            this.y = y;
        }
    }

    public ECPointConverter() {
        super(ECPoint.class, ECPointConverter.Point.class);
    }

    @Override
    public ECPointConverter.Point stepIn(final ECPoint q) {
        final ECPoint normQ = q.normalize();
        return new Point(
            normQ.getXCoord().toBigInteger(), normQ.getYCoord().toBigInteger());
    }

    @Override
    public ECPoint stepOut(final Point point) throws CryptographyException {
        return convert(point.x, point.y);
    }

    /**
     * convert a point into an ECPoint, if it's a valid point on Bletchley's
     * EC curve.
     * @param pointX x coordinate of the point
     * @param pointY y coordinate of the point
     * @return
     * @throws CryptographyException if the point isn't on the curve
     */
    public static ECPoint convert(BigInteger pointX, BigInteger pointY) throws CryptographyException {
        final ECCurve curve = Ec.DOMAIN_PARAMETERS.getCurve();
        final ECPoint res = curve.createPoint(pointX, pointY);
        final ECPoint normRes = res.normalize();
        final ECFieldElement x = normRes.getXCoord();
        if (!normRes.getYCoord().square().equals(
            x.multiply(x.square().add(curve.getA())).add(curve.getB()))) {
            throw new CryptographyException("Point is not on curve");
        }
        return res;
    }
}
