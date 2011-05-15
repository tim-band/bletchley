package net.lshift.spki.convert;

import net.lshift.spki.SExp;

public class SExpConverter
    implements Converter<SExp>
{
    @Override
    public SExp fromSexp(SExp sexp)
    {
        return sexp;
    }

    @Override
    public SExp toSexp(SExp o)
    {
        return o;
    }
}
