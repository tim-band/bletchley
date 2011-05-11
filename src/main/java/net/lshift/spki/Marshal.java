package net.lshift.spki;

import static net.lshift.spki.Create.list;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * Marshal S-expressions into canonical form, and parse them out again.
 *
 * FIXME: the parser is too smart; I'd rather have two parsers, one
 * which reads canonical sexps from binary streams, and another that
 * reads pretty-printed sexps from character streams.
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
            Atom h = ((SList) sexp).getHead();
            SExp[] t = ((SList) sexp).getSparts();
            marshal(ob, h);
            for (int i = 0; i < t.length; i++) {
                marshal(ob, t[i]);
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
                "A ByteArrayOutputStream should never throw an IOException!", e);
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

    private static SExp unmarshal(InputStream is) throws ParseException, IOException {
        List<SExp> resl = new ArrayList<SExp>(1);
        unmarshal(resl, is);
        if (resl.size() != 1)
            throw new ParseException("Wrong number of components");
        return resl.get(0);
    }

    // FIXME: use a simple parser here and put the complex parser in
    // PrettyPrinter
    private static void unmarshal(List<SExp> current, InputStream is) throws ParseException, IOException {
        Stack<List<SExp>> stack = new Stack<List<SExp>>();
        PushbackInputStream stream = new PushbackInputStream(is);

        int token;
        while ((token = stream.read()) >= 0) {
            if (token == Constants.OPENPAREN) {
                stack.push(current);
                current = new ArrayList<SExp>();
            } else if (token == Constants.CLOSEPAREN) {
                if (stack.isEmpty())
                    throw new ParseException("Overclosed paren");
                if (current.isEmpty())
                    throw new ParseException("Empty sexp");
                SExp head = current.get(0);
                if (!(head instanceof Atom))
                    throw new ParseException("First item in sexp is not atom");
                SList c = list((Atom) head, current.subList(1, current.size()));
                current = stack.pop();
                current.add(c);
            } else if (token >= Constants.DIGITBASE && token < Constants.DIGITBASE + 10) {
                int l = 0;

                while (true) {
                    if (token == Constants.COLON) break;
                    int digit = token - Constants.DIGITBASE;
                    if (digit < 0 || digit > 9)
                        throw new ParseException("Bad format");
                    l *= 10;
                    l += digit; // UNSATISFACTORY: check for overflow?
                    token = stream.read();
                }
                byte[] res = new byte[l];
                if (stream.read(res) != l)
                    throw new ParseException("Truncated format");
                current.add(new Atom(res));
            } else if (token == Constants.DOUBLEQUOTE) {
                ByteArrayOutputStream bs = new ByteArrayOutputStream();
                while (true) {
                    token = stream.read();
                    if (token < 0)
                        throw new ParseException(
                                        "Unterminated quoted string");
                    if (token == Constants.DOUBLEQUOTE) break;
                    // UNSATISFACTORY: handle backslashes properly
                    if (token == Constants.BACKSLASH)
                        throw new ParseException(
                                        "Parser cannot handle bacslashes in quoted strings");
                    bs.write(token);
                }
                current.add(new Atom(bs.toByteArray()));
            } else if (token == Constants.OCTOTHORPE) {
                ByteArrayOutputStream bs = new ByteArrayOutputStream();
                while (true) {
                    token = stream.read();
                    if (token < 0)
                        throw new ParseException("Unterminated hex string");
                    if (token == Constants.OCTOTHORPE) break;
                    bs.write(token);
                }
                current.add(new Atom(Hex.decode(bs.toByteArray())));
            } else if (token == Constants.HBAR) {
                ByteArrayOutputStream bs = new ByteArrayOutputStream();
                while (true) {
                    token = stream.read();
                    if (token < 0)
                        throw new ParseException(
                                        "Unterminated base64 string");
                    if (token == Constants.HBAR) break;
                    bs.write(token);
                }
                current.add(new Atom(Base64.decode(bs.toByteArray())));
            } else if (token == Constants.OPENBRACE) {
                ByteArrayOutputStream bs = new ByteArrayOutputStream();
                while (true) {
                    token = stream.read();
                    if (token < 0)
                        throw new ParseException(
                                        "Unterminated base64 section");
                    if (token == Constants.CLOSEBRACE) break;
                    bs.write(token);
                }
                ByteArrayInputStream bis = new ByteArrayInputStream(
                        Base64.decode(bs.toByteArray()));
                unmarshal(current, bis);
            } else if (token == 0x09 || token == 0x0a || token == 0x0b
                            || token == 0x0c || token == 0x0d || token == 0x20) {
                // White space, ignore it.
            } else {
                // Assume a white-space-terminated token. Is this overgenerous?

                ByteArrayOutputStream bs = new ByteArrayOutputStream();
                while (true) {
                    if (token < 0)
                        throw new ParseException(
                                        "Unterminated quoted string");
                    if (token == 0x09 || token == 0x0a || token == 0x0b
                                    || token == 0x0c || token == 0x0d
                                    || token == 0x20 || token == Constants.OPENPAREN
                                    || token == Constants.CLOSEPAREN) {
                        stream.unread(token);
                        break;
                    }
                    // UNSATISFACTORY: check for a whole load of disallowed
                    // characters
                    bs.write(token);
                    token = stream.read();
                }
                current.add(new Atom(bs.toByteArray()));
            }
        }
        if (!stack.isEmpty())
            throw new ParseException("Unclosed paren");
    }

    public static byte[] sha384(SExp sexp) {
        // FIXME: shouldn't need to write out the whole message to digest it
        SHA384Digest digester = new SHA384Digest();
        byte[] message = marshal(sexp);
        digester.update(message, 0, message.length);
        byte[] digest = new byte[digester.getDigestSize()];
        digester.doFinal(digest, 0);
        return digest;
    }
}
