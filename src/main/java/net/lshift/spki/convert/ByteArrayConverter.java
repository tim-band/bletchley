package net.lshift.spki.convert;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;

import java.io.IOException;

import net.lshift.spki.ParseException;

/**
 * Convert between a byte[] and a SExp
 */
public class ByteArrayConverter
    implements Converter<byte[]> {
    // Not a sexp converter, has no name
    @Override public String getName() { return null; }

    @Override
    public Class<byte[]> getResultClass() {
        return byte[].class;
    }

    @Override
    public void write(final ConvertOutputStream out, final byte[] o)
        throws IOException {
        out.atom(o);
    }

    @Override
    public byte[] read(final ConvertInputStream in)
        throws ParseException,
            IOException {
        in.nextAssertType(ATOM);
        return in.atomBytes();
    }
}
