package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.Convert;

/**
 * Serialization format for a raw ECDSA signature
 */
@Convert.ByName("suiteb-p384-ecdsa-signature")
public class EcdsaSignature {
    public final BigInteger r;
    public final BigInteger s;

    public EcdsaSignature(
        BigInteger r,
        BigInteger s
    ) {
        super();
        this.r = r;
        this.s = s;
    }
}
