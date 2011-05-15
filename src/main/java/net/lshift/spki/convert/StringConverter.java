package net.lshift.spki.convert;

import net.lshift.spki.Create;
import net.lshift.spki.SExp;

public class StringConverter
    implements Converter<String>
{
    @Override
    public String fromSexp(SExp sexp)
    {
        return ConvertUtils.toString(sexp);
    }

    @Override
    public SExp toSexp(String o)
    {
        return Create.atom(o);
    }
}
