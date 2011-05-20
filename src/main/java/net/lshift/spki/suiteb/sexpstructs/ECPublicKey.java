package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.PositionBeanConvertible;
import net.lshift.spki.suiteb.EC;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Superclass for serialization formats for EC public keys
 */
public abstract class ECPublicKey
    extends PositionBeanConvertible
{
    public final ECPoint point;

    public ECPublicKey(ECPoint point)
    {
        this.point = point;
    }

    public ECPublicKey(ECPublicKeyParameters params)
    {
        this(params.getQ());
    }

    public ECPublicKey(AsymmetricCipherKeyPair keyPair)
    {
        this((ECPublicKeyParameters) keyPair.getPublic());
    }

    public ECPublicKeyParameters getParameters()
    {
        return EC.toECPublicKeyParameters(point);
    }

    static {
        Point.ensureRegistered();
    }
}
