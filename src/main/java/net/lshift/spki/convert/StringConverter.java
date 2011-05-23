package net.lshift.spki.convert;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;

import java.io.IOException;

import net.lshift.spki.ParseException;

/**
 * Convert between a String and a SExp
 */
public class StringConverter
    implements Converter<String> {
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
