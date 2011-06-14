package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.suiteb.Ec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * Superclass for serialization formats for EC private keys
 */
public abstract class EcPrivateKey {
    public final EcPublicKey publicKey;
    public final BigInteger d;

    public EcPrivateKey(final EcPublicKey publicKey, final BigInteger d) {
        super();
        this.publicKey = publicKey;
        this.d = d;
    }

    public EcPrivateKey(final EcPublicKey publicKey, final AsymmetricCipherKeyPair keyPair) {
        this(publicKey, ((ECPrivateKeyParameters)keyPair.getPrivate()).getD());
    }

    public AsymmetricCipherKeyPair getKeypair() {
        final ECPublicKeyParameters pk = publicKey.getParameters();
        final ECPrivateKeyParameters privk = new ECPrivateKeyParameters(
            d, Ec.DOMAIN_PARAMETERS);
        return new AsymmetricCipherKeyPair(pk, privk);
    }

    static {
        Point.ensureRegistered();
    }
}
