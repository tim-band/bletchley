package net.lshift.spki.convert;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;

import java.io.IOException;
import java.math.BigInteger;

import net.lshift.spki.ParseException;

/**
 * Convert between a BigInteger and a SExp
 */
public class BigIntegerConverter
    implements Converter<BigInteger> {
    // Not a sexp converter, has no name
    @Override public String getName() { return null; }

    @Override
    public Class<BigInteger> getResultClass() {
        return BigInteger.class;
    }

    @Override
    public void write(final ConvertOutputStream out, final BigInteger o)
        throws IOException {
        out.atom(o.toByteArray());
    }

    @Override
    public BigInteger read(final ConvertInputStream in)
        throws ParseException,
            IOException {
        in.nextAssertType(ATOM);
        return new BigInteger(in.atomBytes());
    }
}
