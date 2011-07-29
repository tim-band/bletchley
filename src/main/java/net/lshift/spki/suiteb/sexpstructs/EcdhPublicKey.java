package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for public encryption keys
 */
@Convert.NeedsConverter(ECPointConverter.class)
@Convert.ByPosition(name="suiteb-p384-ecdh-public-key", fields={"point"})
public class EcdhPublicKey extends EcPublicKey {

    public EcdhPublicKey(final ECPoint point) {
        super(point);
    }

    public EcdhPublicKey(final ECPublicKeyParameters publicKey) {
        super(publicKey);
    }

    public EcdhPublicKey(final AsymmetricCipherKeyPair keyPair) {
        super(keyPair);
    }
}
