package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SexpName;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for public encryption keys
 */
@Convert.ByPosition
public class EcdhPublicKey extends EcPublicKey {

    @SexpName("suiteb-p384-ecdh-public-key")
    public EcdhPublicKey(@P("point") ECPoint point) {
        super(point);
    }

    public EcdhPublicKey(ECPublicKeyParameters publicKey) {
        super(publicKey);
    }

    public EcdhPublicKey(AsymmetricCipherKeyPair keyPair) {
        super(keyPair);
    }
}
