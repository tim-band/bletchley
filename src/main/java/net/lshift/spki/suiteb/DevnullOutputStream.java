package net.lshift.spki.suiteb;

import java.io.IOException;
import java.io.OutputStream;

public class DevnullOutputStream
    extends OutputStream {
    @Override
    public void write(int b)
        throws IOException {
        // Discard it
    }

    @Override
    public void write(byte[] b, int off, int len)
        throws IOException {
        // Discard it
    }

    @Override
    public void write(byte[] b)
        throws IOException {
        // Discard it
    }
}
