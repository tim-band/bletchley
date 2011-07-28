package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.Convert;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

/**
 * Serialization format for private signing keys
 */
@Convert.NeedsConvert(Point.class)
@Convert.ByName("suiteb-p384-ecdsa-private-key")
public class EcdsaPrivateKey
    extends EcPrivateKey {

    public EcdsaPrivateKey(
        final EcdsaPublicKey publicKey,
        final BigInteger d
    ) {
        super(publicKey, d);
    }

    public EcdsaPrivateKey(final AsymmetricCipherKeyPair keyPair) {
        super(new EcdsaPublicKey(keyPair), keyPair);
    }
}
