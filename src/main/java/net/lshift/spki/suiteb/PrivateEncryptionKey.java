package net.lshift.spki.suiteb;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.StepConverter;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.suiteb.sexpstructs.EcdhPrivateKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * A private key for decrypting data.
 */
@ConvertClass(PrivateEncryptionKey.Step.class)
public class PrivateEncryptionKey {
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

    public byte[] getKey(final ECPoint ephemeralKey) {
        final ECPublicKeyParameters pk =
            Ec.toECPublicKeyParameters(ephemeralKey);
        return Ec.sessionKey(
            keyPair.getPublic(),
            pk,
            keyPair.getPrivate(),
            pk);
    }

    public static class Step
        extends StepConverter<PrivateEncryptionKey, EcdhPrivateKey> {

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
}
