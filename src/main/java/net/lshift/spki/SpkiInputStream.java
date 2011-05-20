package net.lshift.spki;

import java.io.IOException;
import java.io.InputStream;

public class SpkiInputStream
{
    private final InputStream is;
    private boolean inAtom = false;
    private boolean invalid = false;
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
        if (invalid) {
            throw new ParseException("Stream is dead");
        }
        if (inAtom) {
            invalid = true;
            throw new ParseException("Must read atom first");
        }
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
            inAtom = true;
            return TokenType.ATOM;
        }
    }

    private int readInteger(int next)
        throws ParseException,
            IOException
    {
        int c = next;
        int r = 0;
        for (;;) {
            if (c < Constants.DIGITBASE || c >= Constants.DIGITBASE + 10) {
                invalid = true;
                throw new ParseException("Bad s-expression format");
            }
            r += c - Constants.DIGITBASE;
            c = is.read();
            if (c == Constants.COLON)
                return r;
            if (r >= (Integer.MAX_VALUE - 10)/10) {
                invalid = true;
                throw new ParseException("Integer too large");
            }
            r *= 10;
        }
    }

    public byte[] getBytes() throws IOException, ParseException
    {
        if (invalid) {
            throw new ParseException("Stream is dead");
        }
        if (!inAtom) {
            throw new ParseException("Not in an atom");
        }
        byte[] res = new byte[atomBytes];
        int c = is.read(res);
        if (c != atomBytes) {
            invalid = true;
            throw new ParseException("Failed to read enough bytes");
        }
        inAtom = false;
        return res;
    }

    public void getNextOfType(TokenType type) throws ParseException, IOException
    {
        if (getNext() != type) {
            invalid = true;
            throw new ParseException("Token was of unexpected type");
        }
    }
}
