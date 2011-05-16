package net.lshift.spki.convert;

import net.lshift.spki.SExp;

/**
 * Trivially convert between SExp and SExp - do nothing.
 */
public class SExpConverter
    implements Converter<SExp>
{
    @Override
    public SExp fromSexp(SExp sexp)
    {
        return sexp;
    }

    @Override
    public SExp toSexp(SExp sexp)
    {
        return sexp;
    }
}
