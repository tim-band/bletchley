package net.lshift.spki.sexpform;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import net.lshift.spki.convert.ConvertException;

/**
 * A bracketed list in an SPKI S-expression.  Note that
 * the first item in a list must be an atom.
 */
public final class Slist extends Sexp {
    private final Atom head;
    private final List<Sexp> sparts;

    public Slist(final Atom head, final Sexp[] sparts) {
        super();
        assert head != null;
        assert sparts != null;
        for (final Sexp part: sparts) {
            assert part != null;
        }
        this.head = head;
        this.sparts = Collections.unmodifiableList(
            Arrays.asList(sparts.clone()));
    }

    public Atom getHead() {
        return head;
    }

    public List<Sexp> getSparts() {
        return sparts;
    }

    @Override
    public Slist list()
        throws ConvertException {
        return this;
    }

    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((head == null) ? 0 : head.hashCode());
        result = prime * result + ((sparts == null) ? 0 : sparts.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj)
    {
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        final Slist other = (Slist) obj;
        if (head == null) {
            if (other.head != null) return false;
        } else if (!head.equals(other.head)) return false;
        if (sparts == null) {
            if (other.sparts != null) return false;
        } else if (!sparts.equals(other.sparts)) return false;
        return true;
    }

    @Override
    public String toString()
    {
        final StringBuilder sb = new StringBuilder();
        sb.append('(');
        sb.append(head.toString());
        for (final Sexp s: sparts) {
            sb.append(' ');
            sb.append(s.toString());
        }
        sb.append(')');
        return sb.toString();
    }
}
