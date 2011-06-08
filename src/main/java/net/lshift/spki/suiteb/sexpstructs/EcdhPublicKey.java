package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for public encryption keys
 */
@Convert.ByPosition(name="suiteb-p384-ecdh-public-key", fields={"point"})
public class EcdhPublicKey extends EcPublicKey {

    public EcdhPublicKey(ECPoint point) {
        super(point);
    }

    public EcdhPublicKey(ECPublicKeyParameters publicKey) {
        super(publicKey);
    }

    public EcdhPublicKey(AsymmetricCipherKeyPair keyPair) {
        super(keyPair);
    }
}
