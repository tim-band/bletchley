package net.lshift.spki;

import java.io.IOException;

/**
 * Interface representing a stream of SPKI tokens
 */
public abstract class SpkiInputStream
{
    public enum TokenType {
        ATOM,
        OPENPAREN,
        CLOSEPAREN,
        EOF
    }

    protected enum State {
        TOKEN,
        ATOM,
        FINISHED,
        INVALID
    }

    protected State state = State.TOKEN;

    protected void invalidate()
    {
        state = State.INVALID;
    }

    protected void assertState(State asserted)
    {
        if (this.state != asserted) {
            final State current = this.state;
            invalidate();
            throw new IllegalStateException("State should be "
                + asserted + " but is " + current);
        }
    }

    public TokenType next()
        throws IOException,
            ParseException
    {
        assertState(State.TOKEN);
        TokenType res = doNext();
        switch (res) {
        case ATOM:
            state = State.ATOM;
            break;
        case EOF:
            state = State.FINISHED;
            break;
        default:
            break;
        }
        return res;
    }


    public void nextAssertType(TokenType type)
        throws ParseException,
            IOException
    {
        if (next() != type) {
            invalidate();
            throw new ParseException("Token was of unexpected type");
        }
    }

    public byte[] atomBytes()
        throws IOException,
            ParseException {
        assertState(State.ATOM);
        byte[] res = doAtomBytes();
        state = State.TOKEN;
        return res;
    }

    protected abstract TokenType doNext()
        throws IOException,
            ParseException;

    protected abstract byte[] doAtomBytes()
        throws IOException,
            ParseException;
}
