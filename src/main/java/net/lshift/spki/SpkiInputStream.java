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

    protected boolean invalid = false;

    public abstract TokenType next()
        throws IOException,
            ParseException;

    public abstract byte[] atomBytes()
        throws IOException,
            ParseException;

    public void nextAssertType(TokenType type)
        throws ParseException,
            IOException
    {
        if (next() != type) {
            invalid = true;
            throw new ParseException("Token was of unexpected type");
        }
    }
}
