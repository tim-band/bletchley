package net.lshift.spki.suiteb;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.convert.SexpBacked;
import net.lshift.spki.suiteb.sexpstructs.EcdhPrivateKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

/**
 * A private key for decrypting data.
 */
@ConvertClass(PrivateEncryptionKey.Step.class)
public class PrivateEncryptionKey extends SexpBacked implements SequenceItem {
    private final PublicEncryptionKey publicKey;
    private final AsymmetricCipherKeyPair keyPair;


    private PrivateEncryptionKey(final PublicEncryptionKey publicKey,
                                 final AsymmetricCipherKeyPair keyPair) {
        super();
        this.publicKey = publicKey;
        this.keyPair = keyPair;
    }

    // FIXME: cache this or regenerate every time?
    public PublicEncryptionKey getPublicKey() {
        return publicKey;
    }

    public static PrivateEncryptionKey generate() {
        final AsymmetricCipherKeyPair keyPair = Ec.generate();
        return new PrivateEncryptionKey(
            new PublicEncryptionKey(keyPair.getPublic()),
            keyPair);
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

        public Step() { super(PrivateEncryptionKey.class); }

        @Override
        protected Class<EcdhPrivateKey> getStepClass() {
            return EcdhPrivateKey.class;
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected EcdhPrivateKey stepIn(final PrivateEncryptionKey o) {
            return new EcdhPrivateKey(o.publicKey,
                ((ECPrivateKeyParameters)o.keyPair.getPrivate()).getD());
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected PrivateEncryptionKey stepOut(final EcdhPrivateKey s)
            throws ParseException {
            return new PrivateEncryptionKey(
                s.publicKey,
                s.publicKey.getKeyPair(s.d));
        }
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        engine.addPrivateEncryptionKey(this);
    }
}
