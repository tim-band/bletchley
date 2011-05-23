package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.spki.convert.NameBeanConvertible;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SexpName;

/**
 * Serialization format for a raw ECDSA signature
 */
public class EcdsaSignature
    extends NameBeanConvertible {
    public final BigInteger r;
    public final BigInteger s;

    @SexpName("suiteb-p384-ecdsa-signature")
    public EcdsaSignature(
        @P("r") BigInteger r,
        @P("s") BigInteger s
    ) {
        super();
        this.r = r;
        this.s = s;
    }
}
