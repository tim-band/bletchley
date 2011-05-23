package net.lshift.spki.suiteb;

import net.lshift.spki.convert.PackConvertible;
import net.lshift.spki.suiteb.sexpstructs.EcdhPrivateKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * A private key for decrypting data.
 */
public class PrivateEncryptionKey extends PackConvertible {
    private final AsymmetricCipherKeyPair keyPair;

    private PrivateEncryptionKey(AsymmetricCipherKeyPair keyPair) {
        super();
        this.keyPair = keyPair;
    }

    public static PrivateEncryptionKey unpack(EcdhPrivateKey packed) {
        return new PrivateEncryptionKey(packed.getKeypair());
    }

    @Override
    public EcdhPrivateKey pack() {
        return new EcdhPrivateKey(keyPair);
    }

    // FIXME: cache this or regenerate every time?
    public PublicEncryptionKey getPublicKey() {
        return new PublicEncryptionKey(keyPair.getPublic());
    }

    public static PrivateEncryptionKey generate() {
        return new PrivateEncryptionKey(Ec.generate());
    }

    public byte[] getKey(ECPoint ephemeralKey) {
        ECPublicKeyParameters pk =
            Ec.toECPublicKeyParameters(ephemeralKey);
        return Ec.sessionKey(
            keyPair.getPublic(),
            pk,
            keyPair.getPrivate(),
            pk);
    }
}
