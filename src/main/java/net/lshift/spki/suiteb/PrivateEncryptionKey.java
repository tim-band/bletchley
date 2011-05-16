package net.lshift.spki.suiteb;

import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;
import net.lshift.spki.SExp;
import net.lshift.spki.convert.PackConvertable;
import net.lshift.spki.suiteb.sexpstructs.ECDHMessage;
import net.lshift.spki.suiteb.sexpstructs.ECDHPrivateKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * A private key for decrypting data.
 */
public class PrivateEncryptionKey extends PackConvertable {
    private final AsymmetricCipherKeyPair keyPair;

    private PrivateEncryptionKey(AsymmetricCipherKeyPair keyPair) {
        super();
        this.keyPair = keyPair;
    }

    public static PrivateEncryptionKey unpack(ECDHPrivateKey packed) {
        return new PrivateEncryptionKey(packed.getKeypair());
    }

    public ECDHPrivateKey pack() {
        return new ECDHPrivateKey(keyPair);
    }

    public PublicEncryptionKey getPublicKey() {
        return new PublicEncryptionKey(keyPair.getPublic());
    }

    public static PrivateEncryptionKey generate() {
        return new PrivateEncryptionKey(EC.generate());
    }

    public SExp decrypt(ECDHMessage message)
        throws InvalidCipherTextException,
            ParseException
    {
        ECPublicKeyParameters pk =
            EC.toECPublicKeyParameters(message.getEphemeralKey());
        KeyParameter sessionKey = EC.sessionKey(
                keyPair.getPublic(),
                pk,
                keyPair.getPrivate(),
                pk);
        byte[] ciphertext = message.getCiphertext();
        // FIXME: vary nonce, use associated data
        byte[] nonce = new byte[1];
        nonce[0] = 0;
        AEADParameters aeadparams = new AEADParameters(sessionKey,
                128, nonce, new byte[0]);
        GCMBlockCipher gcm = new GCMBlockCipher(new AESFastEngine());
        gcm.init(false, aeadparams);
        byte[] newtext = new byte[gcm.getOutputSize(ciphertext.length)];
        int pp = 0;
        pp += gcm.processBytes(ciphertext, pp, ciphertext.length, newtext, pp);
        try {
            pp += gcm.doFinal(newtext, pp);
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        }
        return Marshal.unmarshal(newtext);
    }
}
