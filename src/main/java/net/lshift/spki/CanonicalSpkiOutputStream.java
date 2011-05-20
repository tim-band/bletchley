package net.lshift.spki;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Generate a canonical encoding of an S-expression given a stream of tokens.
 */
public class CanonicalSpkiOutputStream implements SpkiOutputStream
{
    private final OutputStream os;

    public CanonicalSpkiOutputStream(OutputStream os)
    {
        this.os = os;
    }

    /* (non-Javadoc)
     * @see net.lshift.spki.SpkiOutputStream#atom(byte[], int, int)
     */
    @Override
    public void atom(byte[] bytes, int off, int len) throws IOException
    {
        os.write(Integer.toString(len).getBytes(Constants.ASCII));
        os.write(':');
        os.write(bytes, off, len);
    }

    /* (non-Javadoc)
     * @see net.lshift.spki.SpkiOutputStream#atom(byte[])
     */
    @Override
    public void atom(byte[] bytes) throws IOException
    {
        atom(bytes, 0, bytes.length);
    }

    /* (non-Javadoc)
     * @see net.lshift.spki.SpkiOutputStream#close()
     */
    @Override
    public void close() throws IOException
    {
        os.close();
    }

    /* (non-Javadoc)
     * @see net.lshift.spki.SpkiOutputStream#beginSexp()
     */
    @Override
    public void beginSexp() throws IOException
    {
        os.write('(');
    }

    /* (non-Javadoc)
     * @see net.lshift.spki.SpkiOutputStream#endSexp()
     */
    @Override
    public void endSexp() throws IOException
    {
        os.write(')');
    }
}
