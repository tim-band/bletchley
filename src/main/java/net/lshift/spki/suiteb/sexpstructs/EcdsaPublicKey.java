package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SexpName;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for public sig verification keys
 */
public class EcdsaPublicKey extends EcPublicKey implements SequenceItem
{
    @SexpName("suiteb-p384-ecdsa-public-key")
    public EcdsaPublicKey(@P("point") ECPoint point)
    {
        super(point);
    }

    public EcdsaPublicKey(ECPublicKeyParameters publicKey)
    {
        super(publicKey);
    }

    public EcdsaPublicKey(AsymmetricCipherKeyPair keyPair)
    {
        super(keyPair);
    }
}
