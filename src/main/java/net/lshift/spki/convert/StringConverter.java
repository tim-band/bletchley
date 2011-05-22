package net.lshift.spki.convert;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;

import java.io.IOException;

import net.lshift.spki.Constants;
import net.lshift.spki.ParseException;
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

    @Override
    public String read(ConvertInputStream in)
        throws ParseException,
            IOException
    {
        in.nextAssertType(ATOM);
        return new String(in.atomBytes(), Constants.UTF8);
    }
}
