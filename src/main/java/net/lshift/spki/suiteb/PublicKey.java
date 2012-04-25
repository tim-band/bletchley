package net.lshift.spki.suiteb;

import net.lshift.spki.convert.Writeable;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A superclass for PublicKey objects
 */
public abstract class PublicKey implements Writeable {
    protected final ECPublicKeyParameters publicKey;
    protected final DigestSha384 keyId;

    @SuppressWarnings("unchecked")
    PublicKey(final CipherParameters publicKey) {
        this.publicKey = (ECPublicKeyParameters) publicKey;
        keyId = DigestSha384.digest(
            (Class<PublicKey>) this.getClass(), this);
    }

    public DigestSha384 getKeyId() {
        return keyId;
    }
}
