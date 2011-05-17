package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for public encryption keys
 */
public class ECDHPublicKey extends ECPublicKey
{
    @SExpName("suiteb-p384-ecdh-public-key")
    public ECDHPublicKey(@P("point") ECPoint point)
    {
        super(point);
    }

    public ECDHPublicKey(ECPublicKeyParameters publicKey)
    {
        super(publicKey);
    }

    public ECDHPublicKey(AsymmetricCipherKeyPair keyPair)
    {
        super(keyPair);
    }
}
