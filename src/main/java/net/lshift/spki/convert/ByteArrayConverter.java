package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.atom;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

/**
 * Convert between a byte[] and a SExp
 */
public class ByteArrayConverter
    implements Converter<byte[]> {
    @Override
    public Class<byte[]> getResultClass() {
        return byte[].class;
    }

    @Override
    public Sexp write(final Converting c, final byte[] o) {
        return atom(o);
    }

    @Override
    public byte[] read(final Converting c, final Sexp in)
        throws InvalidInputException {
        return in.atom().getBytes();
    }
}
