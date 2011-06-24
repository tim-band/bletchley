package net.lshift.spki;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.util.Arrays;

import net.lshift.spki.SpkiInputStream.TokenType;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * Pretty-print an SPKI S-expression.
 */
public class PrettyPrinter extends SpkiOutputStream {
    private final PrintWriter pw;
    private int indent = 0;
    private boolean firstAtom = false;

    public PrettyPrinter(final PrintWriter pw) {
        super();
        this.pw = pw;
    }

    @Override
    public void atom(final byte[] bytes, final int off, final int len)
        throws IOException {
        if (firstAtom) {
            firstAtom = false;
        } else {
            printPrefix();
        }
        if (isText(bytes, off, len)) {
            pw.print("\"");
            pw.print(Constants.ASCII.newDecoder()
                .decode(ByteBuffer.wrap(bytes, off, len)).toString());
            pw.println("\"");
        } else if (len < 10) {
            pw.print("#");
            pw.print(Hex.encodeHexString(Arrays.copyOfRange(bytes, off, off + len)));
            pw.println("#");
        } else {
            pw.print("|");
            pw.print(Base64.encodeBase64String(Arrays.copyOfRange(bytes, off, off + len)));
            pw.println("|");
        }
    }


    @Override
    public void beginSexp()
        throws IOException {
        if (firstAtom) {
            pw.println();
            firstAtom = false;
        }
        printPrefix();
        pw.print('(');
        indent += 1;
        firstAtom = true;
    }

    @Override
    public void endSexp()
        throws IOException {
        if (firstAtom) {
            pw.println();
            firstAtom = false;
        }
        if (indent == 0) {
            throw new RuntimeException("Too many closeparens");
        }
        indent -= 1;
        printPrefix();
        pw.println(")");
    }

    @Override
    public void close()
        throws IOException {
        // Do nothing - don't close underlying PrintStream!
        // Should we assert indent == 0 here?
    }

    private void printPrefix()
    {
        for (int i = 0; i < indent; i++) {
            pw.print("    ");
        }
    }

    private static boolean isText(final byte[] bytes, final int off, final int len)
    {
        if (len ==  0) {
            return false;
        }
        for (int i = 0; i < len; i++) {
            final byte b = bytes[off + i];
            if (b < 0x20 || b >= 0x7f
                    || b == Constants.DOUBLEQUOTE
                    || b == Constants.BACKSLASH)
                return false;
        }
        return true;
    }

    public static void prettyPrint(final PrintWriter out, final InputStream read)
        throws IOException,
            ParseException
    {
        prettyPrint(out, new CanonicalSpkiInputStream(read));
    }

    private static void prettyPrint(
        final PrintWriter out,
        final SpkiInputStream stream) throws IOException, ParseException {
        copyStream(stream, new PrettyPrinter(out));
    }

    public static String prettyPrint(final InputStream read)
        throws ParseException
    {
        StringWriter writer = new StringWriter();
        try {
            prettyPrint(new PrintWriter(writer), read);
        } catch (final IOException e) {
            // should not be possible
            throw new RuntimeException(e);
        }
        return writer.toString();
    }

    public static void copyStream(
        final SpkiInputStream input,
        final SpkiOutputStream output) throws IOException, ParseException {
        for (;;) {
            final TokenType token = input.next();
            switch (token) {
            case ATOM:
                output.atom(input.atomBytes());
                break;
            case OPENPAREN:
                output.beginSexp();
                break;
            case CLOSEPAREN:
                output.endSexp();
                break;
            case EOF:
                output.close();
                return;
            }
        }
    }
}
