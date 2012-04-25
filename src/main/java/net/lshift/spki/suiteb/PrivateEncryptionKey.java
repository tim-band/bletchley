package net.lshift.spki.suiteb;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.convert.SexpBacked;
import net.lshift.spki.suiteb.sexpstructs.EcdhPrivateKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

/**
 * A private key for decrypting data.
 */
@ConvertClass(PrivateEncryptionKey.Step.class)
public class PrivateEncryptionKey extends SexpBacked implements SequenceItem {
    private final AsymmetricCipherKeyPair keyPair;

    private PrivateEncryptionKey(final AsymmetricCipherKeyPair keyPair) {
        super();
        this.keyPair = keyPair;
    }

    // FIXME: cache this or regenerate every time?
    public PublicEncryptionKey getPublicKey() {
        return new PublicEncryptionKey(keyPair.getPublic());
    }

    public static PrivateEncryptionKey generate() {
        return new PrivateEncryptionKey(Ec.generate());
    }

    public AesKey getKeyAsSender(final PublicEncryptionKey receiverKey) {
        return Ec.sessionKey(
            receiverKey.publicKey,
            keyPair.getPublic(),
            keyPair.getPrivate(),
            receiverKey.publicKey);
    }

    public AesKey getKeyAsReceiver(final PublicEncryptionKey senderKey) {
        return Ec.sessionKey(
            keyPair.getPublic(),
            senderKey.publicKey,
            keyPair.getPrivate(),
            senderKey.publicKey);
    }

    public static class Step
        extends ListStepConverter<PrivateEncryptionKey, EcdhPrivateKey> {

        @Override
        public Class<PrivateEncryptionKey> getResultClass() {
            return PrivateEncryptionKey.class;
        }

        @Override
        protected Class<EcdhPrivateKey> getStepClass() {
            return EcdhPrivateKey.class;
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected EcdhPrivateKey stepIn(final PrivateEncryptionKey o) {
            return new EcdhPrivateKey(o.keyPair);
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected PrivateEncryptionKey stepOut(final EcdhPrivateKey s)
            throws ParseException {
            return new PrivateEncryptionKey(s.getKeypair());
        }

    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        engine.addPrivateEncryptionKey(this);
    }
}
