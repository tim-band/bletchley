package net.lshift.spki.convert;

import net.lshift.spki.Create;
import net.lshift.spki.Sexp;

/**
 * Convert between a String and a SExp
 */
public class StringConverter
    implements Converter<String>
{
    @Override
    public String fromSexp(Sexp sexp)
    {
        return ConvertUtils.toString(sexp);
    }

    @Override
    public Sexp toSexp(String string)
    {
        return Create.atom(string);
    }
}
