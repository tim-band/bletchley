package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.atom;

import java.util.Collections;
import java.util.Set;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.schema.AtomType;
import net.lshift.spki.schema.ConverterDeclaration;
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
    public Sexp write(final byte[] o) {
        return atom(o);
    }

    @Override
    public byte[] read(final ConverterCatalog r, final Sexp in)
        throws InvalidInputException {
        return in.atom().getBytes();
    }

    @Override
    public ConverterDeclaration declaration() {
        return new AtomType();
    }

    @Override
    public Set<Class<?>> references() {
        return Collections.emptySet();
    }
}
