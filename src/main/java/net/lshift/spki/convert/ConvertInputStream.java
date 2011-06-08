package net.lshift.spki.convert;

import java.io.IOException;
import java.io.InputStream;
import java.util.Stack;

import net.lshift.spki.CanonicalSpkiInputStream;
import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream;

public class ConvertInputStream
    extends SpkiInputStream {
    private final SpkiInputStream delegate;
    private final Stack<TokenType> tokenStack = new Stack<TokenType>();
    private final Stack<byte[]> byteStack = new Stack<byte[]>();

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
        if (tokenStack.isEmpty()) {
            return delegate.next();
        } else {
            return tokenStack.pop();
        }
    }

    @Override
    public byte[] doAtomBytes()
        throws IOException,
            ParseException {
        if (byteStack.isEmpty()) {
            return delegate.atomBytes();
        } else {
            return byteStack.pop();
        }
    }

    public <T> T read(final Class<T> clazz)
        throws ParseException,
            IOException {
        return Registry.REGISTRY.getConverter(clazz).read(this);
    }

    public void pushback(final TokenType token) {
        switch (token) {
        case EOF:
            assertState(State.FINISHED);
            break;
        case ATOM:
            assertState(State.ATOM);
            break;
        default:
            assertState(State.TOKEN);
            break;
        }
        tokenStack.push(token);
        state = State.TOKEN;
    }

    public void pushback(final byte[] atom) {
        assertState(State.TOKEN);
        byteStack.push(atom);
        state = State.ATOM;
    }

    public void assertAtom(final String name)
        throws ParseException,
            IOException {
        nextAssertType(TokenType.ATOM);
        if (!name.equals(ConvertUtils.stringOrNull(atomBytes()))) {
            throw new ParseException("Did not see expected atom: " + name);
        }
    }
}
