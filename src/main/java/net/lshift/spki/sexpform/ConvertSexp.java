package net.lshift.spki.sexpform;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;
import static net.lshift.spki.sexpform.Create.atom;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.SpkiInputStream;
import net.lshift.spki.SpkiInputStream.TokenType;
import net.lshift.spki.SpkiOutputStream;
import net.lshift.spki.convert.ConvertException;

/**
 * Convert to/from Sexp representation
 */
public class ConvertSexp {
	
	private ConvertSexp() {
		// This class cannot be instantiated
	}
	
    public static void write(final SpkiOutputStream out, final Sexp o)
        throws IOException {
        if (o instanceof Atom) {
            out.atom(((Atom)o).getBytes());
        } else {
            final Slist slist = (Slist)o;
            out.beginSexp();
            out.atom(slist.getHead().getBytes());
            for (final Sexp i: slist.getSparts()) {
                write(out, i);
            }
            out.endSexp();
        }
    }

    private static Slist readRest(final SpkiInputStream in)
        throws IOException, InvalidInputException {
        if (in.next() != ATOM)
            throw new ConvertException("Slist doesn't start with atom");
        final byte [] head = in.atomBytes();
        final List<Sexp> tail = new ArrayList<>();
        for (;;) {
            final TokenType stoken = in.next();
            switch (stoken) {
            case CLOSEPAREN:
                return new Slist(atom(head), tail.toArray(new Sexp[tail.size()]));
            case ATOM:
                tail.add(atom(in.atomBytes()));
                break;
            case OPENPAREN:
                tail.add(readRest(in));
                break;
            case EOF:
                throw new ConvertException("Unexpected EOF");
            }
        }
    }

    public static Sexp read(final SpkiInputStream in)
        throws IOException, InvalidInputException {
        final TokenType token = in.next();
        switch (token) {
        case ATOM:
            return atom(in.atomBytes());
        case OPENPAREN:
            return readRest(in);
        default:
            throw new ConvertException("Unexpected token");
        }
    }
}
