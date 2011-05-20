package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.Atom;
import net.lshift.spki.Sexp;
import net.lshift.spki.Slist;

/**
 * Trivially convert between SExp and SExp - do nothing.
 */
public class SexpConverter
    implements Converter<Sexp>
{
    @Override
    public Sexp fromSexp(Sexp sexp)
    {
        return sexp;
    }

    @Override
    public void write(ConvertOutputStream out, Sexp o)
        throws IOException
    {
        if (o instanceof Atom) {
            out.atom(((Atom)o).getBytes());
        } else {
            Slist slist = (Slist)o;
            out.beginSexp();
            out.atom(slist.getHead().getBytes());
            for (Sexp i: slist.getSparts()) {
                out.write(Sexp.class, i);
            }
            out.endSexp();
        }
    }
}
