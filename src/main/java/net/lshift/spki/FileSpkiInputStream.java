package net.lshift.spki;

import java.io.IOException;
import java.io.InputStream;

/**
 * Superclass for SPKIInputStreams based on reading an InputStream.
 */
public abstract class FileSpkiInputStream extends SpkiInputStream {
    private static final int NO_MORE_DIGITS_BOUND = (Integer.MAX_VALUE - 9)/10;

    protected final InputStream is;

    public FileSpkiInputStream(final InputStream is) {
        this.is = is;
    }

    @Override
    public void close()
        throws IOException {
        is.close();
    }

    protected int readInteger(final int first)
        throws ParseException, IOException {
        int r = first - '0';
        for (;;) {
            final int c = is.read();
            if (c == ':')
                return r;
            if (c < '0' || c > '9') {
                throw new ParseException("Bad s-expression format");
            }
            if (r > NO_MORE_DIGITS_BOUND) {
                // Not a precise test - there are 8 integers
                // at or below MAX_VALUE that this rejects
                throw new ParseException("Integer too large");
            }
            r *= 10;
            r += c - '0';
        }
    }

    protected byte[] readBytes(final int count)
        throws IOException, ParseException {
        final byte[] res = new byte[count];
        int ix = 0;
        while (ix < count) {
            final int c = is.read(res, ix, count-ix);
            if (c < 1) {
                throw new ParseException("Failed to read enough bytes");
            }
            ix += c;
        }
        return res;
    }
}
