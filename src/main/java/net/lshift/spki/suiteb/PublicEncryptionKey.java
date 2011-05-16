package net.lshift.spki.suiteb;

import net.lshift.spki.SExp;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.PackConvertable;
import net.lshift.spki.suiteb.sexpstructs.ECDHMessage;
import net.lshift.spki.suiteb.sexpstructs.ECDHPublicKey;
import net.lshift.spki.suiteb.sexpstructs.EncryptedKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A public key for encrypting data.
 */
public class PublicEncryptionKey extends PackConvertable  {
    private ECPublicKeyParameters publicKey;

    PublicEncryptionKey(CipherParameters publicKey) {
        this.publicKey = (ECPublicKeyParameters) publicKey;
    }

    public static PublicEncryptionKey unpack(ECDHPublicKey sexp) {
        return new PublicEncryptionKey(sexp.getParameters());
    }

    public ECDHPublicKey pack() {
        return new ECDHPublicKey(publicKey);
    }

    public ECDHMessage encrypt(SExp message) {
        AsymmetricCipherKeyPair ephemeralKey = EC.generate();
        byte[] sessionKey = EC.sessionKey(
                publicKey,
                ephemeralKey.getPublic(),
                ephemeralKey.getPrivate(),
                publicKey);
        byte[] payloadKey = EC.getPayloadKey();
        // FIXME: include reference to private key, nonce, and more
        return new ECDHMessage(
            ((ECPublicKeyParameters) ephemeralKey.getPublic()).getQ(),
            EC.symmetricEncrypt(sessionKey,
                Convert.toSExp(EncryptedKey.class, new EncryptedKey(payloadKey))),
            EC.symmetricEncrypt(payloadKey, message));
    }
}
