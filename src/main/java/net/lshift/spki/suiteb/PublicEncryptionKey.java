package net.lshift.spki.suiteb;

import net.lshift.spki.convert.PackConvertable;
import net.lshift.spki.suiteb.sexpstructs.ECDHMessage;
import net.lshift.spki.suiteb.sexpstructs.ECDHPublicKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A public key for encrypting data.
 */
public class PublicEncryptionKey extends PackConvertable  {
    private final ECPublicKeyParameters publicKey;
    private final DigestSha384 keyId;

    PublicEncryptionKey(CipherParameters publicKey) {
        this.publicKey = (ECPublicKeyParameters) publicKey;
        keyId = DigestSha384.digest(
            PublicEncryptionKey.class, this);
    }

    public DigestSha384 getKeyId()
    {
        return keyId;
    }

    public static PublicEncryptionKey unpack(ECDHPublicKey sexp) {
        return new PublicEncryptionKey(sexp.getParameters());
    }

    public ECDHPublicKey pack() {
        return new ECDHPublicKey(publicKey);
    }

    public <T> ECDHMessage encrypt(Class<T> messageType, T message) {
        AsymmetricCipherKeyPair ephemeralKey = EC.generate();
        byte[] sessionKey = EC.sessionKey(
                publicKey,
                ephemeralKey.getPublic(),
                ephemeralKey.getPrivate(),
                publicKey);
        // FIXME: include reference to private key, nonce, and more
        return new ECDHMessage(
            keyId,
            ((ECPublicKeyParameters) ephemeralKey.getPublic()).getQ(),
            EC.symmetricEncrypt(messageType, sessionKey, message));
    }
}
