package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * SExp converter that produces a SExp that looks like key-value pairs
 */
public class NameBeanConverter<T>
    extends BeanFieldConverter<T> {
    public NameBeanConverter(Class<T> clazz) {
        super(clazz);
    }

    @Override
    protected void writeField(
        ConvertOutputStream out,
        FieldConvertInfo field,
        Object property)
        throws IOException {
        out.beginSexp();
        out.atom(field.getHyphenatedName());
        out.writeUnchecked(field.getType(), property);
        out.endSexp();
    }

    @Override
    protected void read(ConvertInputStream in, Object[] initargs)
        throws ParseException,
            IOException {
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

    private FieldConvertInfo getField(byte[] bytes)
        throws ParseException {
        String string = ConvertUtils.stringOrNull(bytes);
        for (FieldConvertInfo field: fields) {
            if (field.getHyphenatedName().equals(string)) {
                return field;
            }
        }
        throw new ParseException("No field matching name found: " + string);
    }
}
