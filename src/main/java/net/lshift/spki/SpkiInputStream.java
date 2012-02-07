package net.lshift.spki;

import java.io.Closeable;
import java.io.IOException;

/**
 * Interface representing a stream of SPKI tokens
 */
public abstract class SpkiInputStream implements Closeable {
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

    protected void assertState(final State asserted)
    {
        if (this.state != asserted) {
            throw new IllegalStateException("State should be "
                + asserted + " but is " + this.state);
        }
    }

    public TokenType next()
        throws IOException,
            ParseException
    {
        assertState(State.TOKEN);
        boolean success = false;
        try {
            final TokenType res = doNext();
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
            success = true;
            return res;
        } finally {
            if (!success) state = State.INVALID;
        }
    }

    public byte[] atomBytes()
        throws IOException,
            ParseException {
        assertState(State.ATOM);
        boolean success = false;
        try {
            final byte[] res = doAtomBytes();
            if (res == null) {
                throw new RuntimeException("doAtomBytes returned null");
            }
            state = State.TOKEN;
            success = true;
            return res;
        } finally {
            if (!success) state = State.INVALID;
        }
    }

    protected abstract TokenType doNext()
        throws IOException, ParseException;

    protected abstract byte[] doAtomBytes()
        throws IOException, ParseException;
}
