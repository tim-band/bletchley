package net.lshift.spki.suiteb;

import net.lshift.spki.convert.SexpBacked;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A superclass for PublicKey objects
 */
public abstract class PublicKey extends SexpBacked {
    protected final ECPublicKeyParameters publicKey;
    protected final DigestSha384 keyId;

    PublicKey(final CipherParameters publicKey) {
        this.publicKey = (ECPublicKeyParameters) publicKey;
        keyId = DigestSha384.digest(this);
    }

    public DigestSha384 getKeyId() {
        return keyId;
    }
}
