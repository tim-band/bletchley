package net.lshift.spki.convert;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;

import java.io.IOException;

import net.lshift.spki.ParseException;

/**
 * Convert between a String and a SExp
 */
public class StringConverter
    implements Converter<String> {
    // Not a sexp converter, has no name
    @Override public String getName() { return null; }

    @Override
    public Class<String> getResultClass() {
        return String.class;
    }

    @Override
    public void write(ConvertOutputStream out, String o)
        throws IOException {
        out.atom(o);
    }

    @Override
    public String read(ConvertInputStream in)
        throws ParseException,
            IOException {
        in.nextAssertType(ATOM);
        return ConvertUtils.string(in.atomBytes());
    }
}
