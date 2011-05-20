package net.lshift.spki;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Date;

/**
 * Static methods useful for creating S-expression structures.
 * Designed to be imported statically.
 */
public class Create {
    public static Sexp atom(byte[] bytes) {
        return new Atom(bytes);
    }

    public static Atom atom(String name) {
        return new Atom(name.getBytes(Constants.UTF8));
    }

    public static Atom atom(BigInteger bi) {
        return new Atom(bi.toByteArray());
    }

    public static Atom atom(Date d) {
        return atom(Constants.DATE_FORMAT.format(d));
    }

    public static Atom atom(int i)
    {
        return atom(BigInteger.valueOf(i));
    }

    public static Slist list(Atom head, Sexp... tail) {
        return new Slist(head, tail);
    }

    public static Slist list(String head, Sexp... tail) {
        return list(atom(head), tail);
    }

    public static Slist list(Atom head, Collection<Sexp> tail) {
        return list(head, tail.toArray(new Sexp[tail.size()]));
    }

    public static Slist list(String head, Collection<Sexp> tail) {
        return list(atom(head), tail);
    }

    public static Slist list(String head, BigInteger value) {
        return list(head, atom(value));
    }
}
