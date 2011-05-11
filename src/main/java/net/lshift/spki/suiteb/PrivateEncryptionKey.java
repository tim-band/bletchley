package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.list;

import java.math.BigInteger;

import net.lshift.spki.Atom;
import net.lshift.spki.Get;
import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;
import net.lshift.spki.SExp;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * A private key for encrypting data.
 */
public class PrivateEncryptionKey {
    private final AsymmetricCipherKeyPair keyPair;

    private PrivateEncryptionKey(AsymmetricCipherKeyPair keyPair) {
        super();
        this.keyPair = keyPair;
    }

    public static PrivateEncryptionKey generate() {
        return new PrivateEncryptionKey(EC.generate());
    }

    public PublicEncryptionKey getPublicKey() {
        return new PublicEncryptionKey(keyPair.getPublic());
    }

    public SExp decrypt(SExp message)
    throws InvalidCipherTextException, ParseException {
        ECPublicKeyParameters pk = EC.toECPublicKeyParameters(
                Get.get(1, message));
        KeyParameter sessionKey = EC.sessionKey(
                keyPair.getPublic(),
                pk,
                keyPair.getPrivate(),
                pk);
        byte[] ciphertext = ((Atom)Get.get(2, message)).getBytes();
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

    public SExp toSExp() {
        return list("suiteb-p384-ecdh-private-key",
            EC.toSExp((ECPublicKeyParameters)keyPair.getPublic()),
            list("d", ((ECPrivateKeyParameters)keyPair.getPrivate()).getD())
        );
    }

    public static PrivateEncryptionKey fromSExp(SExp sexp) {
        ECPublicKeyParameters pk = EC.toECPublicKeyParameters(
                Get.getSExp(EC.ECDH_PUBLIC_KEY, sexp));
        BigInteger d = Get.getBigInteger("d", sexp);
        ECPrivateKeyParameters privk = new ECPrivateKeyParameters(d, EC.domainParameters);
        return new PrivateEncryptionKey(new AsymmetricCipherKeyPair(pk, privk));
    }
}
