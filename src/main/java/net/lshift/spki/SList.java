package net.lshift.spki;

import java.util.Arrays;

/**
 * A bracketed list in an SPKI S-expression.  Note that
 * the first item in a list must be an atom.
 */
public final class SList implements SExp {
    private final Atom head;
    private final SExp sparts[];

    public SList(Atom head, SExp[] sparts) {
        super();
        assert head != null;
        assert sparts != null;
        for (SExp part: sparts) {
            assert part != null;
        }
        this.head = head;
        this.sparts = sparts;
    }

    public Atom getHead() {
        return head;
    }

    public SExp[] getSparts() {
        return sparts;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + head.hashCode();
        result = prime * result + Arrays.hashCode(sparts);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SList other = (SList) obj;
        if (!head.equals(other.head))
            return false;
        if (!Arrays.equals(sparts, other.sparts))
            return false;
        return true;
    }
}
