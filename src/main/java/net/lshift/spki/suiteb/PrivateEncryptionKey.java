package net.lshift.spki.suiteb;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.PackConvertable;
import net.lshift.spki.suiteb.sexpstructs.ECDHMessage;
import net.lshift.spki.suiteb.sexpstructs.ECDHPrivateKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A private key for decrypting data.
 */
public class PrivateEncryptionKey extends PackConvertable {
    private final AsymmetricCipherKeyPair keyPair;

    private PrivateEncryptionKey(AsymmetricCipherKeyPair keyPair) {
        super();
        this.keyPair = keyPair;
    }

    public static PrivateEncryptionKey unpack(ECDHPrivateKey packed) {
        return new PrivateEncryptionKey(packed.getKeypair());
    }

    @Override
    public ECDHPrivateKey pack() {
        return new ECDHPrivateKey(keyPair);
    }

    // FIXME: cache this or regenerate every time?
    public PublicEncryptionKey getPublicKey() {
        return new PublicEncryptionKey(keyPair.getPublic());
    }

    public static PrivateEncryptionKey generate() {
        return new PrivateEncryptionKey(EC.generate());
    }

    public <T> T decrypt(Class<T> payloadType, ECDHMessage message)
        throws InvalidCipherTextException,
            ParseException
    {
        if (!getPublicKey().getKeyId().equals(message.recipient)) {
            throw new RuntimeException("Wrong recipient");
        }
        ECPublicKeyParameters pk =
            EC.toECPublicKeyParameters(message.ephemeralKey);
        byte[] sessionKey = EC.sessionKey(
                keyPair.getPublic(),
                pk,
                keyPair.getPrivate(),
                pk);
        return EC.symmetricDecrypt(payloadType,
            sessionKey, message.ciphertext);
    }
}
