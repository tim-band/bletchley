package net.lshift.spki.convert;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream.TokenType;
import net.lshift.spki.sexpform.Atom;
import net.lshift.spki.sexpform.Create;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.sexpform.Slist;

/**
 * Convert to/from Sexp representation
 */
public class SexpConverter
    implements Converter<Sexp> {
    // Not a sexp converter, has no name
    @Override public String getName() { return null; }

    @Override
    public Class<Sexp> getResultClass() {
        return Sexp.class;
    }

    @Override
    public void write(final ConvertOutputStream out, final Sexp o)
        throws IOException {
        if (o instanceof Atom) {
            out.atom(((Atom)o).getBytes());
        } else {
            final Slist slist = (Slist)o;
            out.beginSexp();
            out.atom(slist.getHead().getBytes());
            for (final Sexp i: slist.getSparts()) {
                out.write(Sexp.class, i);
            }
            out.endSexp();
        }
    }

    @Override
    public Sexp read(final ConvertInputStream in)
        throws ParseException,
            IOException {
        final TokenType token = in.next();
        switch (token) {
        case ATOM:
            return new Atom(in.atomBytes());
        case OPENPAREN:
            in.nextAssertType(ATOM);
            final byte [] head = in.atomBytes();
            final List<Sexp> tail = new ArrayList<Sexp>();
            for (;;) {
                final TokenType stoken = in.next();
                switch (stoken) {
                case CLOSEPAREN:
                    return Create.list(new Atom(head), tail);
                case ATOM:
                    tail.add(new Atom(in.atomBytes()));
                    break;
                case OPENPAREN:
                    in.nextAssertType(ATOM);
                    in.pushback(ATOM);
                    in.pushback(TokenType.OPENPAREN);
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
