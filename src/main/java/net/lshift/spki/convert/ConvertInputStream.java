package net.lshift.spki.convert;

import java.io.IOException;
import java.io.InputStream;

import net.lshift.spki.CanonicalSpkiInputStream;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream;

/**
 * Input stream that wraps an SpkiInputStream to add facilities
 * useful for conversion to classes.
 */
public class ConvertInputStream
    extends SpkiInputStream {
    private final SpkiInputStream delegate;

    public ConvertInputStream(final SpkiInputStream delegate) {
        super();
        this.delegate = delegate;
    }

    public ConvertInputStream(final InputStream is) {
        this(new CanonicalSpkiInputStream(is));
    }

    @Override
    public TokenType doNext()
        throws IOException,
            ParseException {
        return delegate.next();
    }

    @Override
    public byte[] doAtomBytes()
        throws IOException,
            ParseException {
        return delegate.atomBytes();
    }

    @Override
    public void close()
        throws IOException {
        delegate.close();
    }

    public <T> T read(final Class<T> clazz)
        throws IOException, InvalidInputException {
        return Registry.getConverter(clazz).read(this);
    }

    public <T> T readRest(final Class<T> clazz)
            throws IOException, InvalidInputException {
        return ((ListConverter<T>)Registry.getConverter(clazz)).readRest(this);
    }

    public void nextAssertType(final TokenType type)
        throws IOException, InvalidInputException {
        if (next() != type) {
            throw new ConvertException("Token was of unexpected type");
        }
    }

    public void assertAtom(final String name)
        throws InvalidInputException, IOException {
        nextAssertType(TokenType.ATOM);
        if (!name.equals(ConvertUtils.stringOrNull(atomBytes()))) {
            throw new ConvertException("Did not see expected atom: " + name);
        }
    }
}
