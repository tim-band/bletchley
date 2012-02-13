package net.lshift.spki.sexpform;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;
import static net.lshift.spki.sexpform.Create.atom;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.SpkiInputStream.TokenType;
import net.lshift.spki.convert.ConvertException;
import net.lshift.spki.convert.ConvertInputStream;
import net.lshift.spki.convert.ConvertOutputStream;
import net.lshift.spki.convert.Converter;

/**
 * Convert to/from Sexp representation
 */
public class SexpConverter
    implements Converter<Sexp> {
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
        throws IOException, InvalidInputException {
        final TokenType token = in.next();
        switch (token) {
        case ATOM:
            return atom(in.atomBytes());
        case OPENPAREN:
            in.nextAssertType(ATOM);
            final byte [] head = in.atomBytes();
            final List<Sexp> tail = new ArrayList<Sexp>();
            for (;;) {
                final TokenType stoken = in.peek();
                switch (stoken) {
                case CLOSEPAREN:
                    in.next(); // consume peeked token
                    return new Slist(atom(head), tail.toArray(new Sexp[tail.size()]));
                case ATOM:
                    in.next(); // consume peeked token
                    tail.add(atom(in.atomBytes()));
                    break;
                case OPENPAREN:
                    tail.add(in.read(Sexp.class));
                    break;
                case EOF:
                    throw new ConvertException("Unexpected EOF");
                }
            }
        default:
            throw new ConvertException("Unexpected token");
        }
    }
}
