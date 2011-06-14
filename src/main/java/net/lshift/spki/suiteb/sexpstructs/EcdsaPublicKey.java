package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for public sig verification keys
 */
@Convert.ByPosition(name="suiteb-p384-ecdsa-public-key", fields={"point"})
public class EcdsaPublicKey
    extends EcPublicKey {
    public EcdsaPublicKey(ECPoint point) {
        super(point);
    }

    public EcdsaPublicKey(ECPublicKeyParameters publicKey) {
        super(publicKey);
    }

    public EcdsaPublicKey(AsymmetricCipherKeyPair keyPair) {
        super(keyPair);
    }
}
