package net.lshift.spki;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;

import net.lshift.spki.SpkiInputStream.TokenType;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * Pretty-print an SPKI S-expression.
 */
public class PrettyPrinter extends SpkiOutputStream {
    private final PrintStream ps;
    private int indent = 0;
    private boolean firstAtom = false;

    public PrettyPrinter(PrintStream ps) {
        super();
        this.ps = ps;
    }

    @Override
    public void atom(byte[] bytes, int off, int len)
        throws IOException {
        if (firstAtom) {
            firstAtom = false;
        } else {
            printPrefix();
        }
        if (isText(bytes, off, len)) {
            ps.print("\"");
            ps.write(bytes, off, len);
            ps.println("\"");
        } else if (len < 10) {
            ps.print("#");
            Hex.encode(bytes, off, len, ps);
            ps.println("#");
        } else {
            ps.print("|");
            Base64.encode(bytes, off, len, ps);
            ps.println("|");
        }
    }

    @Override
    public void beginSexp()
        throws IOException {
        if (firstAtom) {
            ps.println();
            firstAtom = false;
        }
        printPrefix();
        ps.print('(');
        indent += 1;
        firstAtom = true;
    }

    @Override
    public void endSexp()
        throws IOException {
        if (firstAtom) {
            ps.println();
            firstAtom = false;
        }
        if (indent == 0) {
            throw new RuntimeException("Too many closeparens");
        }
        indent -= 1;
        printPrefix();
        ps.println(")");
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
            ps.print("    ");
        }
    }

    private static boolean isText(byte[] bytes, int off, int len)
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

    public static void prettyPrint(PrintStream out, InputStream read)
        throws IOException,
            ParseException
    {
        prettyPrint(out, new CanonicalSpkiInputStream(read));
    }

    private static void prettyPrint(
        PrintStream out,
        SpkiInputStream stream) throws IOException, ParseException {
        copyStream(stream, new PrettyPrinter(out));
    }

    public static String prettyPrint(InputStream read)
        throws ParseException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            prettyPrint(new PrintStream(baos), read);
        } catch (IOException e) {
            // should not be possible
            throw new RuntimeException(e);
        }
        return new String(baos.toByteArray(), Constants.ASCII);
    }

    public static void copyStream(
        SpkiInputStream input,
        SpkiOutputStream output) throws IOException, ParseException {
        for (;;) {
            TokenType token = input.next();
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
