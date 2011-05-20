package net.lshift.spki;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * Pretty-print an SPKI S-expression.
 */
public class PrettyPrinter {
    public static void prettyPrint(PrintStream ps, String prefix, Sexp sexp)
            throws IOException {
        if (sexp instanceof Atom) {
            byte[] bytes = ((Atom) sexp).getBytes();
            boolean text = (bytes.length > 0);
            for (int i = 0; text && i < bytes.length; i++) {
                if (bytes[i] < 0x20 || bytes[i] >= 0x7f
                        || bytes[i] == Constants.DOUBLEQUOTE
                        || bytes[i] == Constants.BACKSLASH)
                    text = false;
            }
            if (text) {
                ps.print(prefix);
                ps.print("\"");
                ps.write(bytes);
                ps.println("\"");
            } else if (bytes.length < 10) {
                ps.print(prefix);
                ps.print("#");
                ps.write(Hex.encode(bytes));
                ps.println("#");
            } else {
                ps.print(prefix);
                ps.print("|");
                ps.write(Base64.encode(bytes));
                ps.println("|");
            }
        } else {
            List<Sexp> sparts = ((Slist) sexp).getSparts();
            ps.print(prefix);
            ps.print("(\"");
            ps.write(((Slist) sexp).getHead().getBytes());
            ps.println("\"");
            for (Sexp part: sparts) {
                prettyPrint(ps, prefix + "    ", part);
            }
            ps.print(prefix);
            ps.println(")");
        }
    }

    public static void prettyPrint(OutputStream os, Sexp sexp)
    throws IOException {
        PrintStream ps;
        try {
            ps = (PrintStream) os;
        } catch (ClassCastException e) {
            ps = new PrintStream(os);
        }
        prettyPrint(ps, "", sexp);
    }

    public static String prettyPrint(Sexp sexp)
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            prettyPrint(baos, sexp);
        } catch (IOException e) {
            // should not be possible
            throw new RuntimeException(e);
        }
        return new String(baos.toByteArray(), Constants.ASCII);
    }

}
