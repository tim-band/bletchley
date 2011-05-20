package net.lshift.spki;

import java.io.IOException;

/**
 * Interface representing a stream of SPKI tokens
 */
public interface SpkiInputStream
{
    public enum TokenType {
        ATOM,
        OPENPAREN,
        CLOSEPAREN,
        EOF
    }

    public abstract TokenType next()
        throws IOException,
            ParseException;

    public abstract byte[] atomBytes()
        throws IOException,
            ParseException;

    public abstract void nextAssertType(TokenType type)
        throws ParseException,
            IOException;
}
