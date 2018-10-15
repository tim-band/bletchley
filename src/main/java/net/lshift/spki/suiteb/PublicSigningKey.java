package net.lshift.spki.suiteb;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.suiteb.sexpstructs.EcdsaPublicKey;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * A public key for verifying signatures
 */
@ConvertClass(PublicSigningKey.Step.class)
public class PublicSigningKey
    extends PublicKey
    implements SequenceItem {
    private final ECDSASigner signer = new ECDSASigner();

    PublicSigningKey(final CipherParameters publicKey) {
        super(publicKey);
        signer.init(false, publicKey);
    }

    public boolean validate(final DigestSha384 digest, final EcdsaSignature sigVal) {
        return signer.verifySignature(digest.getBytes(), sigVal.r, sigVal.s);
    }

    public static class Step
            extends ListStepConverter<PublicSigningKey, EcdsaPublicKey> {

        public Step() {
            super(PublicSigningKey.class, EcdsaPublicKey.class);
        }

        @Override
        protected EcdsaPublicKey stepIn(final PublicSigningKey o) {
            return new EcdsaPublicKey(o.publicKey);
        }

        @Override
        protected PublicSigningKey stepOut(final EcdsaPublicKey s)
            throws ParseException {
            return new PublicSigningKey(s.getParameters());
        }
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        engine.addPublicSigningKey(this);
        engine.addItemTrust(keyId, trust);
    }
}
