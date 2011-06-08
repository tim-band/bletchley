package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.Convert;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

/**
 * Serialization format for private encryption keys
 */
@Convert.ByName("suiteb-p384-ecdh-private-key")
public class EcdhPrivateKey
    extends EcPrivateKey {

    public EcdhPrivateKey(
        EcdhPublicKey publicKey,
        BigInteger d
    ) {
        super(publicKey, d);
    }

    public EcdhPrivateKey(AsymmetricCipherKeyPair keyPair) {
        super(new EcdhPublicKey(keyPair), keyPair);
    }
}
