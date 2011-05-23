package net.lshift.spki;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * Pretty-print an SPKI S-expression.
 */
public class PrettyPrinter {
    public static void prettyPrint(PrintStream ps, SpkiInputStream stream)
        throws IOException,
            ParseException
    {
        int indent = 0;
        for (;;) {
            switch (stream.next()) {
            case ATOM:
                printPrefix(ps, indent);
                byte[] bytes = stream.atomBytes();
                boolean text = (bytes.length > 0);
                for (int i = 0; text && i < bytes.length; i++) {
                    if (bytes[i] < 0x20 || bytes[i] >= 0x7f
                            || bytes[i] == Constants.DOUBLEQUOTE
                            || bytes[i] == Constants.BACKSLASH)
                        text = false;
                }
                if (text) {
                    ps.print("\"");
                    ps.write(bytes);
                    ps.println("\"");
                } else if (bytes.length < 10) {
                    ps.print("#");
                    ps.write(Hex.encode(bytes));
                    ps.println("#");
                } else {
                    ps.print("|");
                    ps.write(Base64.encode(bytes));
                    ps.println("|");
                }
                break;
            case CLOSEPAREN:
                if (indent == 0) {
                    throw new ParseException("Too many closeparens");
                }
                indent -= 1;
                printPrefix(ps, indent);
                ps.println(")");
                break;
            case OPENPAREN:
                printPrefix(ps, indent);
                ps.println("(");
                indent += 1;
                break;
            case EOF:
                return;
            }
        }
    }

    private static void printPrefix(PrintStream ps, int indent)
    {
        for (int i = 0; i < indent; i++) {
            ps.print("    ");
        }
    }

    public static String prettyPrint(
        CanonicalSpkiInputStream stream) throws ParseException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            prettyPrint(new PrintStream(baos), stream);
        } catch (IOException e) {
            // should not be possible
            throw new RuntimeException(e);
        }
        return new String(baos.toByteArray(), Constants.ASCII);
    }

}
