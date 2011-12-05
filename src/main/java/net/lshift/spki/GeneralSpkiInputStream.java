package net.lshift.spki;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

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
            case ' ': case '\n': case '\r': case '\t': case '\f':
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
                atomBytes = getStream(AcceptSomeBytes.STRING, next);
                return TokenType.ATOM;
            case '#':
                atomBytes = Hex.decode(getStream(AcceptSomeBytes.HEX, next));
                return TokenType.ATOM;
            case '|':
                atomBytes = Base64.decode(getStream(AcceptSomeBytes.BASE64, next));
                return TokenType.ATOM;
            default:
                if (next < 'a' || next > 'z') {
                    invalidate();
                    throw new ParseException("Can't handle token: " + next);
                }
                ByteArrayOutputStream r = new ByteArrayOutputStream();
                r.write(next);
                pushback = AcceptSomeBytes.TOKEN.accept(r, is);
                atomBytes = r.toByteArray();
                return TokenType.ATOM;
            }
        }
    }

    private byte[] getStream(AcceptSomeBytes accept, int terminator)
                    throws ParseException, IOException {
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        final int last = accept.accept(s, is);
        if (last != terminator) {
            throw new ParseException("Can't handle token: " + last);
        }
        return s.toByteArray();
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
