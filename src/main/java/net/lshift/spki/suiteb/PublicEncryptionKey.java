package net.lshift.spki.suiteb;

import java.util.List;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.StepConverter;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.suiteb.sexpstructs.EcdhItem;
import net.lshift.spki.suiteb.sexpstructs.EcdhPublicKey;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A public key for encrypting data.
 */
@ConvertClass(PublicEncryptionKey.Step.class)
public class PublicEncryptionKey extends PublicKey implements SequenceItem  {
    PublicEncryptionKey(CipherParameters publicKey) {
        super(publicKey);
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

    public static class Step
        extends StepConverter<PublicEncryptionKey, EcdhPublicKey> {
        @Override
        public Class<PublicEncryptionKey> getResultClass() {
            return PublicEncryptionKey.class;
        }

        @Override
        protected Class<EcdhPublicKey> getStepClass() {
            return EcdhPublicKey.class;
        }

        @Override
        protected EcdhPublicKey stepIn(PublicEncryptionKey o) {
            return new EcdhPublicKey(o.publicKey);
        }

        @Override
        protected PublicEncryptionKey stepOut(EcdhPublicKey s)
            throws ParseException {
            return new PublicEncryptionKey(s.getParameters());
        }
    }
}
