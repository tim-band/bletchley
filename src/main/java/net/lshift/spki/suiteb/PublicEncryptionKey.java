package net.lshift.spki.suiteb;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.suiteb.sexpstructs.EcdhPublicKey;

import org.bouncycastle.crypto.CipherParameters;

/**
 * A public key for encrypting data.
 */
@ConvertClass(PublicEncryptionKey.Step.class)
public class PublicEncryptionKey extends PublicKey implements SequenceItem {
    PublicEncryptionKey(final CipherParameters publicKey) {
        super(publicKey);
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

    @Override
    public void process(InferenceEngine engine, Condition trust)
        throws InvalidInputException {
        engine.addPublicEncryptionKey(this);
    }
}
