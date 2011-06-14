package net.lshift.spki;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Generate a canonical encoding of an S-expression given a stream of tokens.
 */
public class CanonicalSpkiOutputStream
    extends SpkiOutputStream {
    private final OutputStream os;

    public CanonicalSpkiOutputStream(final OutputStream os) {
        this.os = os;
    }

    @Override
    public void atom(final byte[] bytes, final int off, final int len)
        throws IOException {
        os.write(Integer.toString(len).getBytes(Constants.ASCII));
        os.write(':');
        os.write(bytes, off, len);
    }

    @Override
    public void close()
        throws IOException {
        os.close();
    }

    @Override
    public void beginSexp()
        throws IOException {
        os.write('(');
    }

    @Override
    public void endSexp()
        throws IOException {
        os.write(')');
    }
}
