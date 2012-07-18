package net.lshift.spki.suiteb;

import java.math.BigInteger;

import net.lshift.spki.convert.SexpBacked;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A superclass for PublicKey objects
 */
public abstract class PublicKey extends SexpBacked {
    protected final ECPublicKeyParameters publicKey;
    protected DigestSha384 keyId = null;

    PublicKey(final CipherParameters publicKey) {
        this.publicKey = (ECPublicKeyParameters) publicKey;
    }

    public synchronized DigestSha384 getKeyId() {
        if (keyId == null) {
            keyId = DigestSha384.digest(this);
        }
        return keyId;
    }

    public AsymmetricCipherKeyPair getKeyPair(final BigInteger d) throws CryptographyException {
        if (!publicKey.getQ().equals(Ec.DOMAIN_PARAMETERS.getG().multiply(d))) {
            throw new CryptographyException("Private key does not match public");
        }
        return new AsymmetricCipherKeyPair(publicKey,
            new ECPrivateKeyParameters(d, Ec.DOMAIN_PARAMETERS));
    }
}
