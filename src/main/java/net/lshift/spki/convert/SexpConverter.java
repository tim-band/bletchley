package net.lshift.spki.convert;

import net.lshift.spki.Sexp;

/**
 * Trivially convert between SExp and SExp - do nothing.
 */
public class SexpConverter
    implements Converter<Sexp>
{
    @Override
    public Sexp fromSexp(Sexp sexp)
    {
        return sexp;
    }

    @Override
    public Sexp toSexp(Sexp sexp)
    {
        return sexp;
    }
}
