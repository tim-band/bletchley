package net.lshift.spki.suiteb;

import java.io.IOException;
import java.io.OutputStream;

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
