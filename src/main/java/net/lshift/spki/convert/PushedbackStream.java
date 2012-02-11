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
        this.delegate = getUnderlying(delegate);
        this.pushedBack = pushedBack;
    }

    private static SpkiInputStream getUnderlying(SpkiInputStream delegate) {
        if (delegate instanceof PushedbackStream) {
            return ((PushedbackStream)delegate).getUnderlying();
        }
        return delegate;
    }

    private SpkiInputStream getUnderlying() {
        if (pushedBack == null) {
            // If you're going to read from the delegate,
            // you can never read from us again
            invalidate();
            return getUnderlying(delegate);
        }
        return this;
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
