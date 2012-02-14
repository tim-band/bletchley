package net.lshift.spki.suiteb;

import java.util.List;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.suiteb.sexpstructs.EcdhItem;
import net.lshift.spki.suiteb.sexpstructs.EcdhPublicKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A public key for encrypting data.
 */
@ConvertClass(PublicEncryptionKey.Step.class)
public class PublicEncryptionKey extends PublicKey {
    PublicEncryptionKey(final CipherParameters publicKey) {
        super(publicKey);
    }

    public EncryptionSetup setupEncrypt() {
        final AsymmetricCipherKeyPair ephemeralKey = Ec.generate();
        final AesKey key = Ec.sessionKey(
                publicKey,
                ephemeralKey.getPublic(),
                ephemeralKey.getPrivate(),
                publicKey);
        final EcdhItem encryptedKey = new EcdhItem(
            keyId,
            ((ECPublicKeyParameters) ephemeralKey.getPublic()).getQ());
        return new EncryptionSetup(
            encryptedKey,
            key);
    }

    public AesKey setupEncrypt(final List<SequenceItem> toSend) {
        final EncryptionSetup setup = setupEncrypt();
        toSend.add(setup.encryptedKey);
        return setup.key;
    }

    public static class Step
        extends ListStepConverter<PublicEncryptionKey, EcdhPublicKey> {
        @Override
        public Class<PublicEncryptionKey> getResultClass() {
            return PublicEncryptionKey.class;
        }

        @Override
        protected Class<EcdhPublicKey> getStepClass() {
            return EcdhPublicKey.class;
        }

        @Override
        protected EcdhPublicKey stepIn(final PublicEncryptionKey o) {
            return new EcdhPublicKey(o.publicKey);
        }

        @Override
        protected PublicEncryptionKey stepOut(final EcdhPublicKey s)
            throws ParseException {
            return new PublicEncryptionKey(s.getParameters());
        }
    }
}
