package net.lshift.spki;

import static net.lshift.spki.Create.list;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

    public static void marshal(OutputStream os, Sexp sexp) throws IOException
    {
        marshal(new SpkiOutputStream(os), sexp);
    }

    public static byte[] marshal(Sexp sexp) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            marshal(baos, sexp);
        } catch (IOException e) {
            throw new RuntimeException(
                "A ByteArrayOutputStream should never throw an IOException", e);
        }
        return baos.toByteArray();
    }

    public static Sexp unmarshal(byte[] bytes) throws ParseException {
        try {
            return unmarshal(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            throw new RuntimeException("Impossible!", e);
        }
    }

    public static Sexp unmarshal(InputStream is)
        throws ParseException,
            IOException
   {
        return unmarshal(new SpkiInputStream(is));
    }

    public static Sexp unmarshal(SpkiInputStream is)
        throws ParseException,
            IOException
    {
        List<Sexp> current = new ArrayList<Sexp>(1);
        Stack<List<Sexp>> stack = new Stack<List<Sexp>>();

        for (;;) {
            TokenType token = is.getNext();
            switch (token) {
            case EOF:
                if (!stack.isEmpty())
                    throw new ParseException("Unclosed paren");
                if (current.size() != 1)
                    throw new ParseException("Wrong number of components");
                return current.get(0);
            case ATOM:
                current.add(new Atom(is.getBytes()));
                break;
            case OPENPAREN:
                stack.push(current);
                current = new ArrayList<Sexp>();
                // First item in a SExp must be an atom
                is.getNextOfType(TokenType.ATOM);
                current.add(new Atom(is.getBytes()));
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
