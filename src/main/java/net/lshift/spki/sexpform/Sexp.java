package net.lshift.spki.sexpform;

import net.lshift.spki.convert.ConvertException;

/**
 * SPKI S-expression type.  Should have only two implementors,
 * @see Atom
 * @see Slist
 */
public class Sexp {
    public Atom atom() throws ConvertException {
        throw new ConvertException("atom expected, list found");
    }

    public Slist list() throws ConvertException {
        throw new ConvertException("list expected, atom found");
    }
}
