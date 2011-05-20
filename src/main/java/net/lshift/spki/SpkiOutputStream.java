package net.lshift.spki;

import java.io.Closeable;
import java.io.IOException;

/**
 * Interface representing a stream to which SPKI tokens can be written
 */
public interface SpkiOutputStream extends Closeable
{
    public abstract void atom(byte[] bytes, int off, int len)
        throws IOException;

    public abstract void atom(byte[] bytes)
        throws IOException;

    @Override
    public abstract void close()
        throws IOException;

    public abstract void beginSexp()
        throws IOException;

    public abstract void endSexp()
        throws IOException;

}
