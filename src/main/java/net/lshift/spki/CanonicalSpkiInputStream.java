package net.lshift.spki;

import java.io.IOException;
import java.io.InputStream;

/**
 * Tokenize an InputStream into SPKI tokens
 */
public class CanonicalSpkiInputStream extends SpkiInputStream {
    private static final int NO_MORE_DIGITS_BOUND = (Integer.MAX_VALUE - 9)/10;
    private final InputStream is;
    private int atomBytes;

    public CanonicalSpkiInputStream(InputStream is) {
        this.is = is;
    }

    @Override
    public TokenType doNext()
        throws IOException,
            ParseException {
        int next = is.read();
        switch (next) {
        case '(':
            return TokenType.OPENPAREN;
        case ')':
            return TokenType.CLOSEPAREN;
        case -1:
            return TokenType.EOF;
        default:
            atomBytes = readInteger(next);
            return TokenType.ATOM;
        }
    }

    private int readInteger(int next)
        throws ParseException,
            IOException {
        int c = next;
        int r = 0;
        for (;;) {
            if (c < Constants.DIGITBASE || c >= Constants.DIGITBASE + 10) {
                invalidate();
                throw new ParseException("Bad s-expression format");
            }
            r += c - Constants.DIGITBASE;
            c = is.read();
            if (c == Constants.COLON)
                return r;
            if (r > NO_MORE_DIGITS_BOUND) {
                // Could strictly speaking handle it so long as
                // next digit is 0..7 and is last, but let's not go mad.
                invalidate();
                throw new ParseException("Integer too large");
            }
            r *= 10;
        }
    }

    @Override
    public byte[] doAtomBytes()
        throws IOException,
            ParseException {
        byte[] res = new byte[atomBytes];
        int c = is.read(res);
        if (c != atomBytes) {
            invalidate();
            throw new ParseException("Failed to read enough bytes");
        }
        return res;
    }

    @Override
    public void close() throws IOException {
        is.close();
    }
}
