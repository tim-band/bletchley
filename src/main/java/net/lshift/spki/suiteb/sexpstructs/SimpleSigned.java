package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.SExp;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

/**
 * Simple signature format - just a message and a bare signature.
 *
 * FIXME: we should use real SPKI signatures and "sequence" sexps.
 */
public class SimpleSigned extends PositionBeanConvertable
{
    public final SExp object;
    public final ECDSASignature signature;

    @SExpName("simple-signed")
    public SimpleSigned(
        @P("object") SExp object,
        @P("signature") ECDSASignature signature
    ) {
        super();
        this.object = object;
        this.signature = signature;
    }

    public SExp getObject()
    {
        return object;
    }

    public ECDSASignature getSignature()
    {
        return signature;
    }
}
