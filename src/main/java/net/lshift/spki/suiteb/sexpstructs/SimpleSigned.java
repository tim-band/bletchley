package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.SExp;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionalSexp;

// FIXME: replace this with a real SPKI signature
public class SimpleSigned
{
    private final SExp object;
    private final ECDSASignature signature;

    @PositionalSexp("simple-signed")
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
