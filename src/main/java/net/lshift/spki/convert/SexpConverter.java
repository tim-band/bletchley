package net.lshift.spki.convert;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.Atom;
import net.lshift.spki.Create;
import net.lshift.spki.ParseException;
import net.lshift.spki.Sexp;
import net.lshift.spki.Slist;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * Convert to/from Sexp representation
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

    @Override
    public Sexp read(ConvertInputStream in)
        throws ParseException,
            IOException
    {
        TokenType token = in.next();
        switch (token) {
        case ATOM:
            return new Atom(in.atomBytes());
        case OPENPAREN:
            in.nextAssertType(ATOM);
            byte [] head = in.atomBytes();
            List<Sexp> tail = new ArrayList<Sexp>();
            for (;;) {
                TokenType stoken = in.next();
                switch (stoken) {
                case CLOSEPAREN:
                    return Create.list(new Atom(head), tail);
                case ATOM:
                    tail.add(new Atom(in.atomBytes()));
                    break;
                case OPENPAREN:
                    in.nextAssertType(ATOM);
                    in.pushback(in.atomBytes());
                    tail.add(in.read(Sexp.class));
                    break;
                case EOF:
                    throw new ParseException("Unexpected EOF");
                }
            }
        default:
            throw new ParseException("Unexpected token");
        }
    }
}