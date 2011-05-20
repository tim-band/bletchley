package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SexpName;

/**
 * Serialization format for private encryption keys
 */
public class EcdhPrivateKey extends EcPrivateKey
{
    @SexpName("suiteb-p384-ecdh-private-key")
    public EcdhPrivateKey(
        @P("publicKey") EcdhPublicKey publicKey,
        @P("d") BigInteger d)
    {
        super(publicKey, d);
    }

    public EcdhPrivateKey(AsymmetricCipherKeyPair keyPair)
    {
        super(new EcdhPublicKey(keyPair), keyPair);
    }
}
