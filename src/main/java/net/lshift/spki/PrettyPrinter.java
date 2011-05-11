package net.lshift.spki;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * Pretty-print an SPKI S-expression.
 */
public class PrettyPrinter {
    public static void prettyPrint(PrintStream ps, String prefix, SExp sexp)
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
            SExp[] sparts = ((SList) sexp).getSparts();
            ps.print(prefix);
            ps.print("(\"");
            ps.write(((SList) sexp).getHead().getBytes());
            ps.println("\"");
            for (int i = 0; i < sparts.length; i++) {
                prettyPrint(ps, prefix + "    ", sparts[i]);
            }
            ps.print(prefix);
            ps.println(")");
        }
    }

    public static void prettyPrint(OutputStream os, SExp sexp)
    throws IOException {
        PrintStream ps;
        try {
            ps = (PrintStream) os;
        } catch (ClassCastException e) {
            ps = new PrintStream(os);
        }
        prettyPrint(ps, "", sexp);
    }

}
