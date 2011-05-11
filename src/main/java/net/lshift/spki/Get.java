package net.lshift.spki;

import java.math.BigInteger;

/**
 * Static methods useful for extracting information from
 * S-expression structures.
 *
 * FIXME: This is meant as a stopgap -
 * I want to write a smart, stricter deserializer into
 * annotated classes.
 */
public class Get {
    public static BigInteger getBigInteger(String string, SExp sexp) {
        return new BigInteger(getBytes(string, sexp));
    }

    public static byte[] getBytes(String string, SExp sexp) {
        return ((Atom)get(1, getSExp(string, sexp))).getBytes();
    }

    public static SExp get(int i, SExp sexp) {
        return ((SList)sexp).getSparts()[i-1];
    }

    public static SExp getSExp(String string, SExp sexp) {
        Atom match = Create.atom(string);
        for (SExp s: ((SList)sexp).getSparts()) {
            if (s instanceof SList) {
                SList sl = (SList) s;
                if (match.equals(sl.getHead())) {
                    return sl;
                }
            }
        }
        throw new GetException("No sexp with key " + string
                + " found in sexp " + ((SList)sexp).getHead().getBytes());
    }
}
