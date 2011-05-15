package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.SExp;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

// FIXME: replace this with a real SPKI signature
public class SimpleSigned extends PositionBeanConvertable
{
    private final SExp object;
    private final ECDSASignature signature;

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
