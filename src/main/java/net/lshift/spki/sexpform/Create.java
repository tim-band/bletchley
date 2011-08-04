package net.lshift.spki.sexpform;

import net.lshift.spki.Constants;

/**
 * Static methods useful for creating S-expression structures.
 * Designed to be imported statically.
 */
public class Create {
    public static Atom atom(final byte[] bytes) {
        return new Atom(bytes);
    }

    public static Atom atom(final String name) {
        return atom(name.getBytes(Constants.UTF8));
    }

    public static Slist list(final String head, final Sexp... tail) {
        return new Slist(atom(head), tail);
    }
}
