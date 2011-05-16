package net.lshift.spki.suiteb;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.PackConvertable;
import net.lshift.spki.suiteb.sexpstructs.ECDHMessage;
import net.lshift.spki.suiteb.sexpstructs.ECDHPrivateKey;
import net.lshift.spki.suiteb.sexpstructs.EncryptedKey;

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

    public ECDHPrivateKey pack() {
        return new ECDHPrivateKey(keyPair);
    }

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
        ECPublicKeyParameters pk =
            EC.toECPublicKeyParameters(message.getEphemeralKey());
        byte[] sessionKey = EC.sessionKey(
                keyPair.getPublic(),
                pk,
                keyPair.getPrivate(),
                pk);
        EncryptedKey payloadKey = EC.symmetricDecrypt(EncryptedKey.class,
            sessionKey, message.getEncryptedPayloadKey());
        return EC.symmetricDecrypt(payloadType,
            payloadKey.getKey(), message.getCiphertext());
    }
}
