package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for public sig verification keys
 */
public class ECDSAPublicKey extends ECPublicKey implements SequenceItem
{
    @SExpName("suiteb-p384-ecdsa-public-key")
    public ECDSAPublicKey(@P("point") ECPoint point)
    {
        super(point);
    }

    public ECDSAPublicKey(ECPublicKeyParameters publicKey)
    {
        super(publicKey);
    }

    public ECDSAPublicKey(AsymmetricCipherKeyPair keyPair)
    {
        super(keyPair);
    }
}
