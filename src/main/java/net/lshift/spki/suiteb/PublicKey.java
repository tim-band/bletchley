package net.lshift.spki.suiteb;

import net.lshift.spki.convert.SexpBacked;

import org.bouncycastle.crypto.CipherParameters;
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
}
