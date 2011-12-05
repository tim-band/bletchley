package net.lshift.spki;

import java.io.IOException;
import java.io.InputStream;

public abstract class FileSpkiInputStream extends SpkiInputStream {
    private static final int NO_MORE_DIGITS_BOUND = (Integer.MAX_VALUE - 9)/10;

    protected final InputStream is;

    public FileSpkiInputStream(final InputStream is) {
        this.is = is;
    }

    protected int readInteger(final int next)
        throws ParseException, IOException {
        int c = next;
        int r = 0;
        for (;;) {
            if (c < '0' || c > '9') {
                invalidate();
                throw new ParseException("Bad s-expression format");
            }
            r += c - '0';
            c = is.read();
            if (c == ':')
                return r;
            if (r > NO_MORE_DIGITS_BOUND) {
                // Could strictly speaking handle it so long as
                // next digit is 0..7 and is last, but let's not go mad.
                invalidate();
                throw new ParseException("Integer too large");
            }
            r *= 10;
        }
    }

    @Override
    public void close()
        throws IOException {
        is.close();
    }

    protected byte[] readBytes(int count)
        throws IOException,
            ParseException {
                final byte[] res = new byte[count];
                int ix = 0;
                while (ix < count) {
                    final int c = is.read(res, ix, count-ix);
                    if (c < 1) {
                        invalidate();
                        throw new ParseException("Failed to read enough bytes");
                    }
                    ix += c;
                }
                return res;
            }
}
