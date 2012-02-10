package net.lshift.spki;

import java.io.IOException;
import java.io.InputStream;

/**
 * Tokenize an InputStream into SPKI tokens
 */
public class CanonicalSpkiInputStream extends FileSpkiInputStream {
    int atomBytes;

    public CanonicalSpkiInputStream(final InputStream is) {
        super(is);
    }

    @Override
    public TokenType doNext()
        throws IOException,
            ParseException {
        final int next = is.read();
        switch (next) {
        case '(':
            return TokenType.OPENPAREN;
        case ')':
            return TokenType.CLOSEPAREN;
        case -1:
            return TokenType.EOF;
        case '1': case '2': case '3': case '4': case '5':
        case '6': case '7': case '8': case '9':
            atomBytes = readInteger(next);
            return TokenType.ATOM;
        case '0':
            if (is.read() != ':')
                throw new ParseException("Bad s-expression format");
            atomBytes = 0;
            return TokenType.ATOM;
        default:
            throw new ParseException("Bad s-expression format");
        }
    }

    @Override
    public byte[] doAtomBytes()
        throws IOException,
            ParseException {
        return readBytes(atomBytes);
    }
}
