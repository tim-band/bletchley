package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * Superclass for converters that look for a constructor
 * annotated with the sexp name.
 */
public abstract class BeanConverter<T>
    implements ListConverter<T> {
    protected final Class<T> clazz;
    protected final String name;

    public BeanConverter(final Class<T> clazz, final String name) {
        this.clazz = clazz;
        this.name = name;
    }

    @Override
    public Class<T> getResultClass() {
        return clazz;
    }

    /* (non-Javadoc)
     * @see net.lshift.spki.convert.ListConverter#getName()
     */
    @Override
    public String getName() {
        return name;
    }

    /* (non-Javadoc)
     * @see net.lshift.spki.convert.ListConverter#readRest(net.lshift.spki.convert.ConvertInputStream)
     */
    @Override
    public abstract T readRest(ConvertInputStream in)
            throws IOException, InvalidInputException;

    @Override
    public T read(final ConvertInputStream in) throws IOException,
            InvalidInputException {
        in.nextAssertType(TokenType.OPENPAREN);
        in.assertAtom(name);
        return readRest(in);
    }

    protected void writeName(final ConvertOutputStream out)
        throws IOException {
        out.atom(name);
    }
}
