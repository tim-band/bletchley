package net.lshift.spki.convert;

import java.io.IOException;
import java.util.Stack;

import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream;

public class ConvertInputStream extends SpkiInputStream
{
    private final SpkiInputStream delegate;
    private Stack<TokenType> tokenStack = new Stack<TokenType>();
    private Stack<byte[]> byteStack = new Stack<byte[]>();

    public ConvertInputStream(SpkiInputStream delegate)
    {
        super();
        this.delegate = delegate;
    }

    @Override
    public TokenType doNext()
        throws IOException,
            ParseException
    {
        if (tokenStack.isEmpty()) {
            return delegate.next();
        } else {
            return tokenStack.pop();
        }
    }

    @Override
    public byte[] doAtomBytes()
        throws IOException,
            ParseException
    {
        if (byteStack.isEmpty()) {
            return delegate.atomBytes();
        } else {
            return byteStack.pop();
        }
    }

    public <T> T read(Class<T> clazz)
        throws ParseException,
            IOException
    {
        return Registry.REGISTRY.getConverter(clazz).read(this);
    }

    public void pushback(TokenType token)
    {
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

    public void pushback(byte[] atom)
    {
        assertState(State.TOKEN);
        byteStack.push(atom);
        state = State.ATOM;
    }

    public void assertAtom(String name)
        throws ParseException,
            IOException
    {
        nextAssertType(TokenType.ATOM);
        if (!name.equals(ConvertUtils.stringOrNull(atomBytes()))) {
            throw new ParseException("Did not see expected atom: " + name);
        }
    }
}
