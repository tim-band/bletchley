package net.lshift.spki.convert;

import java.io.IOException;

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
    public void write(ConvertOutputStream out, String o)
        throws IOException
    {
        out.atom(o);
    }
}
