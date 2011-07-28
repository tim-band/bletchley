package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for public sig verification keys
 */
@Convert.NeedsConvert(Point.class)
@Convert.ByPosition(name="suiteb-p384-ecdsa-public-key", fields={"point"})
public class EcdsaPublicKey
    extends EcPublicKey {
    public EcdsaPublicKey(final ECPoint point) {
        super(point);
    }

    public EcdsaPublicKey(final ECPublicKeyParameters publicKey) {
        super(publicKey);
    }

    public EcdsaPublicKey(final AsymmetricCipherKeyPair keyPair) {
        super(keyPair);
    }
}
