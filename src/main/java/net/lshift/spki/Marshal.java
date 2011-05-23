package net.lshift.spki;

import static net.lshift.spki.Create.list;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * Marshal S-expressions into canonical form, and parse them out again.
 */
public class Marshal {
    public static void marshal(SpkiOutputStream ob, Sexp sexp)
        throws IOException
    {
        if (sexp instanceof Atom) {
            ob.atom(((Atom)sexp).getBytes());
        } else {
            final Slist slist = (Slist) sexp;
            ob.beginSexp();
            ob.atom(slist.getHead().getBytes());
            for (Sexp p: slist.getSparts()) {
                marshal(ob, p);
            }
            ob.endSexp();
        }
    }

    public static Sexp unmarshal(SpkiInputStream is)
        throws ParseException,
            IOException
    {
        List<Sexp> current = new ArrayList<Sexp>(1);
        Stack<List<Sexp>> stack = new Stack<List<Sexp>>();

        for (;;) {
            TokenType token = is.next();
            switch (token) {
            case EOF:
                if (!stack.isEmpty())
                    throw new ParseException("Unclosed paren");
                if (current.size() != 1)
                    throw new ParseException("Wrong number of components");
                return current.get(0);
            case ATOM:
                current.add(new Atom(is.atomBytes()));
                break;
            case OPENPAREN:
                stack.push(current);
                current = new ArrayList<Sexp>();
                // First item in a SExp must be an atom
                is.nextAssertType(TokenType.ATOM);
                current.add(new Atom(is.atomBytes()));
                break;
            case CLOSEPAREN:
                if (stack.isEmpty())
                    throw new ParseException("Overclosed paren");
                Slist c = list((Atom) current.get(0),
                    current.subList(1, current.size()));
                current = stack.pop();
                current.add(c);
                break;
            }
        }
    }
}
