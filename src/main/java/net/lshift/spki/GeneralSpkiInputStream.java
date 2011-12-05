package net.lshift.spki;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class GeneralSpkiInputStream extends FileSpkiInputStream {
    private static final int NO_PUSHBACK = -2;
    private byte[] atomBytes = null;
    private int pushback = NO_PUSHBACK;

    public GeneralSpkiInputStream(InputStream is) {
        super(is);
    }

    @Override
    protected TokenType doNext()
        throws IOException,
            ParseException {
        while (true) {
            final int next = read();
            switch (next) {
            case ' ':
            case '\n':
            case '\r':
            case '\t':
            case '\f':
                break;
            case '(':
                return TokenType.OPENPAREN;
            case ')':
                return TokenType.CLOSEPAREN;
            case -1:
                return TokenType.EOF;
            case '1': case '2': case '3': case '4': case '5':
            case '6': case '7': case '8': case '9':
                int byteCount = readInteger(next);
                atomBytes = readBytes(byteCount);
                return TokenType.ATOM;
            case '\"':
                ByteArrayOutputStream q = new ByteArrayOutputStream();
                while (true) {
                    final int b = is.read();
                    if (b == '\"') {
                        atomBytes = q.toByteArray();
                        return TokenType.ATOM;
                    }
                    if (b < 0x20 || b >= 0x7f || b == '\\') {
                        throw new ParseException("Can't handle token: " + next);
                    }
                    q.write(b);
                }
            default:
                if (next < 'a' || next > 'z') {
                    invalidate();
                    throw new ParseException("Can't handle token: " + next);
                }
                ByteArrayOutputStream r = new ByteArrayOutputStream();
                r.write(next);
                while (true) {
                    final int b = is.read();
                    if ((b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-') {
                        atomBytes = r.toByteArray();
                        pushback = b;
                        return TokenType.ATOM;
                    }
                    r.write(b);
                }
            }
        }
    }

    private int read() throws IOException {
        if (pushback == NO_PUSHBACK) {
            return is.read();
        } else {
            final int res = pushback;
            pushback = NO_PUSHBACK;
            return res;
        }
    }

    @Override
    protected byte[] doAtomBytes()
        throws IOException,
            ParseException {
        byte[] res = atomBytes;
        atomBytes = null;
        return res;
    }
}
