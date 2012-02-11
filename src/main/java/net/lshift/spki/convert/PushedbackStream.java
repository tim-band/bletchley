package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream;

/**
 * Yields a single provided token, then defers to the underlying stream.
 */
public class PushedbackStream extends SpkiInputStream {
    private final SpkiInputStream delegate;
    private TokenType pushedBack;

    public PushedbackStream(SpkiInputStream delegate, TokenType pushedBack) {
        super();
        this.delegate = delegate;
        this.pushedBack = pushedBack;
    }

    public TokenType doNext() throws IOException, ParseException {
        if (pushedBack != null) {
            try {
                return pushedBack;
            } finally {
                pushedBack = null;
            }
        } else {
            return delegate.next();
        }
    }

    public byte[] doAtomBytes() throws IOException, ParseException {
        return delegate.atomBytes();
    }

    public void close() throws IOException {
        delegate.close();
    }


}
