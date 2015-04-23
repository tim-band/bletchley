package net.lshift.spki;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;

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

    protected final InputStream is;

    public SpkiInputStream(final InputStream is) {
        this.is = is;
    }

    @Override
    public void close()
            throws IOException {
        is.close();
    }

    protected State state = State.TOKEN;

    protected void assertState(final State asserted)
    {
        if (this.state != asserted) {
            throw new IllegalStateException("State should be "
                + asserted + " but is " + this.state);
        }
    }

    public void invalidate() {
        state = State.INVALID;
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
            if (!success) invalidate();
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
            if (!success) invalidate();
        }
    }

    protected int readInteger(final int first)
            throws ParseException, IOException {
        int curVal = first - '0';
        for (;;) {
            final int c = is.read();
            if (c == ':')
                return curVal;
            if (c < '0' || c > '9') {
                throw new ParseException("Bad s-expression format");
            }
            final int newVal = curVal * 10 + (c - '0');
            if (newVal < curVal) {
                throw new ParseException("Integer too large");
            }
            curVal = newVal;
        }
    }

    protected byte[] readBytes(final int count)
            throws IOException, ParseException {
        final byte[] res = new byte[count];
        int ix = 0;
        while (ix < count) {
            final int c = is.read(res, ix, count-ix);
            if (c < 1) {
                throw new ParseException("Failed to read enough bytes");
            }
            ix += c;
        }
        return res;
    }

    protected abstract TokenType doNext()
        throws IOException, ParseException;

    protected abstract byte[] doAtomBytes()
        throws IOException, ParseException;
}
