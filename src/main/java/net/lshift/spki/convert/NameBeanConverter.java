package net.lshift.spki.convert;

import static net.lshift.spki.Create.atom;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.util.Arrays;

import net.lshift.spki.Atom;
import net.lshift.spki.Constants;
import net.lshift.spki.Create;
import net.lshift.spki.ParseException;
import net.lshift.spki.Sexp;
import net.lshift.spki.Slist;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * SExp converter that produces a SExp that looks like key-value pairs
 */
public class NameBeanConverter<T>
    extends BeanFieldConverter<T>
{
    public NameBeanConverter(Class<T> clazz)
    {
        super(clazz);
    }

    @Override
    protected Sexp fieldToSexp(FieldConvertInfo field, Sexp sexp)
    {
        return Create.list(field.getHyphenatedName(), sexp);
    }

    @Override
    protected void writeField(
        ConvertOutputStream out,
        FieldConvertInfo field,
        Object property) throws IOException
    {
        out.beginSexp();
        out.atom(field.getHyphenatedName());
        out.writeUnchecked(field.getType(), property);
        out.endSexp();
    }

    @Override
    protected Sexp getSExp(
        FieldConvertInfo field,
        int i,
        Slist slist)
    {
        String fieldName = field.getHyphenatedName();
        Atom match = atom(fieldName);
        for (Sexp s: slist.getSparts()) {
            if (s instanceof Slist) {
                Slist sl = (Slist) s;
                if (match.equals(sl.getHead())) {
                    List<Sexp> sparts = sl.getSparts();
                    if (sparts.size() != 1) {
                        throw new ConvertException(
                            "Wrong number of parts for " + fieldName);
                    }
                    return sparts.get(0);
                }
            }
        }
        throw new ConvertException("No sexp with key " + fieldName
                + " found in sexp " + slist.getHead());
    }

    @Override
    protected void read(ConvertInputStream in, Object[] initargs)
        throws ParseException,
            IOException
    {
        in.nextAssertType(TokenType.OPENPAREN);
        in.assertAtom(name);
        for (int i = 0; i < fields.length; i++) {
            in.nextAssertType(TokenType.OPENPAREN);
            in.nextAssertType(TokenType.ATOM);
            FieldConvertInfo field = getField(in.atomBytes());
            initargs[field.getIndex()] = in.read(field.getType());
            in.nextAssertType(TokenType.CLOSEPAREN);
        }
        in.nextAssertType(TokenType.CLOSEPAREN);
    }

    private FieldConvertInfo getField(byte[] bytes) throws ParseException
    {
        for (FieldConvertInfo field: fields) {
            final byte[] nameBytes = field.getName().getBytes(Constants.UTF8);
            if (Arrays.areEqual(nameBytes, bytes)) {
                return field;
            }
        }
        throw new ParseException("No field matching name found");
    }
}
