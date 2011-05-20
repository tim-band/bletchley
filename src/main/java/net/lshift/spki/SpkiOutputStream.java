package net.lshift.spki;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Generate a canonical encoding of an S-expression given a stream of tokens.
 */
public class SpkiOutputStream implements Closeable
{
    private final OutputStream os;

    public SpkiOutputStream(OutputStream os)
    {
        this.os = os;
    }

    public void atom(byte[] bytes, int off, int len) throws IOException
    {
        os.write(Integer.toString(len).getBytes(Constants.ASCII));
        os.write(':');
        os.write(bytes, off, len);
    }

    public void atom(byte[] bytes) throws IOException
    {
        atom(bytes, 0, bytes.length);
    }

    @Override
    public void close() throws IOException
    {
        os.close();
    }

    public void beginSexp() throws IOException
    {
        os.write('(');
    }

    public void endSexp() throws IOException
    {
        os.write(')');
    }
}
