package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SexpName;

/**
 * Serialization format for private signing keys
 */
public class EcdsaPrivateKey
    extends EcPrivateKey {
    @SexpName("suiteb-p384-ecdsa-private-key")
    public EcdsaPrivateKey(
        @P("publicKey") EcdsaPublicKey publicKey,
        @P("d") BigInteger d
    ) {
        super(publicKey, d);
    }

    public EcdsaPrivateKey(AsymmetricCipherKeyPair keyPair) {
        super(new EcdsaPublicKey(keyPair), keyPair);
    }
}
