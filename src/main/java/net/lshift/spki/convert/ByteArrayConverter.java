package net.lshift.spki.convert;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;

import java.io.IOException;

import net.lshift.spki.ParseException;

/**
 * Convert between a byte[] and a SExp
 */
public class ByteArrayConverter
    implements Converter<byte[]> {
    @Override
    public void write(ConvertOutputStream out, byte[] o)
        throws IOException {
        out.atom(o);
    }

    @Override
    public byte[] read(ConvertInputStream in)
        throws ParseException,
            IOException {
        in.nextAssertType(ATOM);
        return in.atomBytes();
    }
}
