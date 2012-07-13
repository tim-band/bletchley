package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.SexpBacked;
import net.lshift.spki.suiteb.Ec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Superclass for serialization formats for EC public keys
 */
public abstract class EcPublicKey extends SexpBacked {
    public final ECPoint point;

    public EcPublicKey(final ECPoint point) {
        this.point = point;
    }

    public EcPublicKey(final ECPublicKeyParameters params) {
        this(params.getQ());
    }

    public EcPublicKey(final AsymmetricCipherKeyPair keyPair) {
        this((ECPublicKeyParameters) keyPair.getPublic());
    }

    public ECPublicKeyParameters getParameters() {
        return Ec.toECPublicKeyParameters(point);
    }
}
