package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.Create.list;
import net.lshift.spki.Marshal;
import net.lshift.spki.SExp;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * A public key for encrypting data.
 */
public class PublicEncryptionKey {
    private ECPublicKeyParameters publicKey;

    PublicEncryptionKey(CipherParameters publicKey) {
        this.publicKey = (ECPublicKeyParameters) publicKey;
    }

    public SExp toSExp() {
        return EC.toSExp(publicKey);
    }

    public static PublicEncryptionKey fromSExp(SExp sexp) {
        return new PublicEncryptionKey(EC.toECPublicKeyParameters(sexp));
    }

    public SExp encrypt(SExp message) {
        AsymmetricCipherKeyPair ephemeralKey = EC.generate();
        KeyParameter sessionKey = EC.sessionKey(
                publicKey,
                ephemeralKey.getPublic(),
                ephemeralKey.getPrivate(),
                publicKey);
        // FIXME: vary nonce, use associated data
        byte[] nonce = new byte[1];
        nonce[0] = 0;
        AEADParameters aeadparams = new AEADParameters(sessionKey,
                128, nonce, new byte[0]);
        GCMBlockCipher gcm = new GCMBlockCipher(new AESFastEngine());
        gcm.init(true, aeadparams);
        byte[] plaintext = Marshal.marshal(message);
        byte[] ciphertext = new byte[gcm.getOutputSize(plaintext.length)];
        int resp = 0;
        resp += gcm.processBytes(plaintext, 0, plaintext.length, ciphertext, resp);
        try {
            resp += gcm.doFinal(ciphertext, resp);
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
        // FIXME: include reference to private key, nonce, and more
        return list("suiteb-p384-ecdh-message",
            EC.toSExp((ECPublicKeyParameters) ephemeralKey.getPublic()),
            atom(ciphertext)
        );
    }
}
