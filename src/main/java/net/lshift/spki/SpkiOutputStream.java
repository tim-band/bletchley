package net.lshift.spki;

import java.io.Closeable;
import java.io.IOException;

/**
 * Interface representing a stream to which SPKI tokens can be written
 */
public abstract class SpkiOutputStream implements Closeable
{
    public abstract void atom(byte[] bytes, int off, int len)
        throws IOException;

    public void atom(byte[] bytes)
        throws IOException {
        atom(bytes, 0, bytes.length);
    }

    @Override
    public abstract void close()
        throws IOException;

    public abstract void beginSexp()
        throws IOException;

    public abstract void endSexp()
        throws IOException;

}
