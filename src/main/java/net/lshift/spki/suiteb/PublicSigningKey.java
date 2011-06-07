package net.lshift.spki.suiteb;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.StepConverter;
import net.lshift.spki.convert.Convert.StepConverted;
import net.lshift.spki.suiteb.sexpstructs.EcdsaPublicKey;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * A public key for verifying signatures
 */
@StepConverted(PublicSigningKey.Step.class)
public class PublicSigningKey
    extends PublicKey
    implements SequenceItem {
    private final ECDSASigner signer = new ECDSASigner();

    PublicSigningKey(CipherParameters publicKey) {
        super(publicKey);
        signer.init(false, publicKey);
    }

    public boolean validate(DigestSha384 digest, EcdsaSignature sigVal) {
        return signer.verifySignature(digest.getBytes(), sigVal.r, sigVal.s);
    }

    public static class Step
        extends StepConverter<PublicSigningKey, EcdsaPublicKey> {

        @Override
        protected Class<PublicSigningKey> getResultClass() {
            return PublicSigningKey.class;
        }

        @Override
        protected Class<EcdsaPublicKey> getStepClass() {
            return EcdsaPublicKey.class;
        }

        @Override
        protected EcdsaPublicKey stepIn(PublicSigningKey o) {
            return new EcdsaPublicKey(o.publicKey);
        }

        @Override
        protected PublicSigningKey stepOut(EcdsaPublicKey s)
            throws ParseException {
            return new PublicSigningKey(s.getParameters());
        }

    }
}
