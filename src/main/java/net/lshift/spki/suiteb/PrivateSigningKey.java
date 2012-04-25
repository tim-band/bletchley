package net.lshift.spki.suiteb;

import java.math.BigInteger;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.convert.SexpBacked;
import net.lshift.spki.suiteb.sexpstructs.EcdsaPrivateKey;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * A private key for signing
 */
@ConvertClass(PrivateSigningKey.Step.class)
public class PrivateSigningKey extends SexpBacked {
    private final AsymmetricCipherKeyPair keyPair;
    private final ECDSASigner signer = new ECDSASigner();

    private PrivateSigningKey(final AsymmetricCipherKeyPair keyPair) {
        super();
        this.keyPair = keyPair;
        signer.init(true, keyPair.getPrivate());
    }

    public PublicSigningKey getPublicKey() {
        return new PublicSigningKey(keyPair.getPublic());
    }

    public static PrivateSigningKey generate() {
        return new PrivateSigningKey(Ec.generate());
    }

    public EcdsaSignature rawSignature(final DigestSha384 digest) {
        final BigInteger[] signature = signer.generateSignature(digest.getBytes());
        return new EcdsaSignature(signature[0], signature[1]);
    }

    public SequenceItem signDigest(final DigestSha384 digest) {
        return new Signature(digest, getPublicKey().getKeyId(),
            rawSignature(digest));
    }

    public SequenceItem sign(final SequenceItem item) {
        return signDigest(DigestSha384.digest(item));
    }

    public static class Step
        extends ListStepConverter<PrivateSigningKey, EcdsaPrivateKey> {
        @Override
        public Class<PrivateSigningKey> getResultClass() {
            return PrivateSigningKey.class;
        }

        @Override
        protected Class<EcdsaPrivateKey> getStepClass() {
            return EcdsaPrivateKey.class;
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected EcdsaPrivateKey stepIn(final PrivateSigningKey o) {
            return new EcdsaPrivateKey(o.keyPair);
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected PrivateSigningKey stepOut(final EcdsaPrivateKey s)
            throws ParseException {
            return new PrivateSigningKey(s.getKeypair());
        }
    }
}
