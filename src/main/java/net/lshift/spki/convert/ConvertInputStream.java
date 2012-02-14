package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream;

/**
 * Input stream that wraps an SpkiInputStream to add facilities
 * useful for conversion to classes.
 */
public class ConvertInputStream extends SpkiInputStream {
    private final SpkiInputStream delegate;
    private TokenType peek = null;

    public ConvertInputStream(final SpkiInputStream delegate) {
        super();
        this.delegate = delegate;
    }

    @Override
    public TokenType doNext()
        throws IOException, ParseException {
        if (peek != null) {
            try {
                return peek;
            } finally {
                peek = null;
            }
        } else {
            return delegate.next();
        }
    }

    @Override
    public byte[] doAtomBytes()
        throws IOException, ParseException {
        return delegate.atomBytes();
    }

    @Override
    public void close()
        throws IOException {
        delegate.close();
    }

    public TokenType peek() throws ParseException, IOException {
        if (peek == null) {
            peek = delegate.next();
        }
        return peek;
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
