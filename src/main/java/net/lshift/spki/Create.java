package net.lshift.spki;

import java.util.Collection;

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
}
