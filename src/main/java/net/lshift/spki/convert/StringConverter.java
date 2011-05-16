package net.lshift.spki.convert;

import net.lshift.spki.Create;
import net.lshift.spki.SExp;

/**
 * Convert between a String and a SExp
 */
public class StringConverter
    implements Converter<String>
{
    @Override
    public String fromSexp(SExp sexp)
    {
        return ConvertUtils.toString(sexp);
    }

    @Override
    public SExp toSexp(String string)
    {
        return Create.atom(string);
    }
}
