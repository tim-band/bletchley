package net.lshift.spki.sexpform;

import net.lshift.spki.convert.Convert;

/**
 * SPKI S-expression type.  Should have only two implementors,
 * @see Atom
 * @see Slist
 */
@Convert.ConvertClass(SexpConverter.class)
public interface Sexp {
    // Define no methods - all in Atom or SList.
}
