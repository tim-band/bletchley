package net.lshift.spki;

import java.io.IOException;
import java.io.InputStream;

public class SpkiInputStream
{
    private final InputStream is;
    private boolean inAtom = false;
    private int atomBytes;

    public enum TokenType {
        ATOM,
        OPENPAREN,
        CLOSEPAREN,
        EOF
    }

    public SpkiInputStream(InputStream is)
    {
        this.is = is;
    }

    public TokenType getNext() throws IOException, ParseException
    {
        int next = is.read();
        if (next == '(') {
            return TokenType.OPENPAREN;
        } else if (next == ')') {
            return TokenType.CLOSEPAREN;
        } else if (next == -1) {
            return TokenType.EOF;
        }
        inAtom = true;
        int r = 0;
        for (;;) {
            if (next < Constants.DIGITBASE || next >= Constants.DIGITBASE + 10) {
                throw new IOException("Bad s-expression format");
            }
            r = r * 10 + (next - Constants.DIGITBASE);
            next = is.read();
            if (next == Constants.COLON)
                break;
            if (r >= (Integer.MAX_VALUE - 10)/10) {
                throw new ParseException("Integer too large");
            }
        }
        atomBytes = r;
        return TokenType.ATOM;
    }

    public byte[] getBytes() throws IOException, ParseException
    {
        if (!inAtom) {
            throw new ParseException("Not in an atom");
        }
        byte[] res = new byte[atomBytes];
        int c = is.read(res);
        if (c != atomBytes) {
            throw new ParseException("Failed to read enough bytes");
        }
        inAtom = false;
        return res;
    }

    public void assertNext(TokenType type) throws ParseException, IOException
    {
        if (getNext() != type) {
            throw new ParseException("Token was of unexpected type");
        }
    }
}
