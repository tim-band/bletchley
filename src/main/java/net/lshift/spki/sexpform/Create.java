package net.lshift.spki.sexpform;

import java.util.Collection;

import net.lshift.spki.Constants;

/**
 * Static methods useful for creating S-expression structures.
 * Designed to be imported statically.
 */
public class Create {
    public static Sexp atom(final byte[] bytes) {
        return new Atom(bytes);
    }

    public static Atom atom(final String name) {
        return new Atom(name.getBytes(Constants.UTF8));
    }

    public static Slist list(final Atom head, final Sexp... tail) {
        return new Slist(head, tail);
    }

    public static Slist list(final String head, final Sexp... tail) {
        return list(atom(head), tail);
    }

    public static Slist list(final Atom head, final Collection<Sexp> tail) {
        return list(head, tail.toArray(new Sexp[tail.size()]));
    }

    public static Slist list(final String head, final Collection<Sexp> tail) {
        return list(atom(head), tail);
    }
}
