package net.lshift.spki.suiteb;

import java.io.IOException;
import java.io.OutputStream;

/**
 * An OutputStream that throws away everything it's given.
 * Used because DigestOutputStream insists on passing on what
 * it's given to another output stream.
 */
public class DevnullOutputStream
    extends OutputStream {
    @Override
    public void write(final int b)
        throws IOException {
        // Discard it
    }

    @Override
    public void write(final byte[] b, final int off, final int len)
        throws IOException {
        // Discard it
    }

    @Override
    public void write(final byte[] b)
        throws IOException {
        // Discard it
    }
}
