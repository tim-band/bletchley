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
    public static void marshal(OutputStream ob, SExp sexp)
        throws IOException
    {
        if (sexp instanceof Atom) {
            byte[] b = ((Atom)sexp).getBytes();
            ob.write(Integer.toString(b.length).getBytes(Constants.UTF8));
            ob.write(Constants.COLON);
            ob.write(b);
        } else {
            ob.write(Constants.OPENPAREN);
            final SList slist = (SList) sexp;
            marshal(ob, slist.getHead());
            for (SExp p: slist.getSparts()) {
                marshal(ob, p);
            }
            ob.write(Constants.CLOSEPAREN);
        }
    }

    public static byte[] marshal(SExp sexp) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            marshal(baos, sexp);
        } catch (IOException e) {
            throw new RuntimeException(
                "A ByteArrayOutputStream should never throw an IOException", e);
        }
        return baos.toByteArray();
    }

    public static SExp unmarshal(byte[] bytes) throws ParseException {
        try {
            return unmarshal(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            throw new RuntimeException("Impossible!", e);
        }
    }

    public static SExp unmarshal(InputStream is)
        throws ParseException,
            IOException
   {
        return unmarshal(new SpkiInputStream(is));
    }

    public static SExp unmarshal(SpkiInputStream is)
        throws ParseException,
            IOException
    {
        List<SExp> current = new ArrayList<SExp>(1);
        Stack<List<SExp>> stack = new Stack<List<SExp>>();

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
                current = new ArrayList<SExp>();
                // First item in a SExp must be an atom
                is.getNextOfType(TokenType.ATOM);
                current.add(new Atom(is.getBytes()));
                break;
            case CLOSEPAREN:
                if (stack.isEmpty())
                    throw new ParseException("Overclosed paren");
                SList c = list((Atom) current.get(0),
                    current.subList(1, current.size()));
                current = stack.pop();
                current.add(c);
                break;
            }
        }
    }
}
