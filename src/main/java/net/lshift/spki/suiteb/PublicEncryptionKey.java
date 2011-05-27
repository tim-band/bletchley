package net.lshift.spki.suiteb;

import java.util.List;

import net.lshift.spki.suiteb.sexpstructs.EcdhItem;
import net.lshift.spki.suiteb.sexpstructs.EcdhPublicKey;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A public key for encrypting data.
 */
public class PublicEncryptionKey extends PublicKey  {
    PublicEncryptionKey(CipherParameters publicKey) {
        super(publicKey);
    }

    public static PublicEncryptionKey unpack(EcdhPublicKey sexp) {
        return new PublicEncryptionKey(sexp.getParameters());
    }

    @Override
    public EcdhPublicKey pack() {
        return new EcdhPublicKey(publicKey);
    }

    public EncryptionSetup setupEncrypt() {
        final AsymmetricCipherKeyPair ephemeralKey = Ec.generate();
        final AesKey key = new AesKey(
            Ec.sessionKey(
                publicKey,
                ephemeralKey.getPublic(),
                ephemeralKey.getPrivate(),
                publicKey));
        final EcdhItem encryptedKey = new EcdhItem(
            keyId,
            ((ECPublicKeyParameters) ephemeralKey.getPublic()).getQ());
        return new EncryptionSetup(
            encryptedKey,
            key);
    }

    public AesKey setupEncrypt(List<SequenceItem> toSend) {
        EncryptionSetup setup = setupEncrypt();
        toSend.add(setup.encryptedKey);
        return setup.key;
    }
}
