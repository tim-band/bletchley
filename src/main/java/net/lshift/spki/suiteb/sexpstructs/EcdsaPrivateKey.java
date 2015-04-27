package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.PublicSigningKey;

/**
 * Serialization format for private signing keys
 */
@Convert.RequiresConverter(ECPointConverter.class)
@Convert.ByName("suiteb-p384-ecdsa-private-key")
public class EcdsaPrivateKey {
    public final PublicSigningKey publicKey;
    public final BigInteger d;

    public EcdsaPrivateKey(final PublicSigningKey publicKey, final BigInteger d) {
        super();
        this.publicKey = publicKey;
        this.d = d;
    }
}
