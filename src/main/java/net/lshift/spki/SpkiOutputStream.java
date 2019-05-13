package net.lshift.spki;

import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;

/**
 * Interface representing a stream to which SPKI tokens can be written
 */
public abstract class SpkiOutputStream implements Closeable, Flushable
{
    public abstract void atom(byte[] bytes, int off, int len)
        throws IOException;

    public abstract void beginSexp()
        throws IOException;

    public abstract void endSexp()
        throws IOException;

    public void atom(final byte[] bytes)
        throws IOException {
        atom(bytes, 0, bytes.length);
    }
}
