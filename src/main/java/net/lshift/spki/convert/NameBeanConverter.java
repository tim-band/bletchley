package net.lshift.spki.convert;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * SExp converter that produces a SExp that looks like key-value pairs
 */
public class NameBeanConverter<T>
    extends BeanFieldConverter<T> {
    public NameBeanConverter(
        Class<T> clazz,
        String name,
        List<FieldConvertInfo> fields) {
        super(clazz, name, fields);
    }

    @Override
    protected void writeField(
        ConvertOutputStream out,
        FieldConvertInfo field,
        Object property)
        throws IOException {
        out.beginSexp();
        out.atom(field.hyphenatedName);
        out.writeUnchecked(field.field.getType(), property);
        out.endSexp();
    }

    @Override
    protected Map<Field, Object> readFields(ConvertInputStream in)
        throws ParseException,
            IOException {
        Map<Field, Object> res = new HashMap<Field, Object>();
        in.nextAssertType(TokenType.OPENPAREN);
        in.assertAtom(name);
        for (int i = 0; i < fields.size(); i++) {
            in.nextAssertType(TokenType.OPENPAREN);
            in.nextAssertType(TokenType.ATOM);
            FieldConvertInfo field = getField(in.atomBytes());
            if (res.containsKey(field.field)) {
                throw new ParseException("Repeated field");
            }
            res.put(field.field, in.read(field.field.getType()));
            in.nextAssertType(TokenType.CLOSEPAREN);
        }
        in.nextAssertType(TokenType.CLOSEPAREN);
        return res;
    }

    private FieldConvertInfo getField(byte[] bytes)
        throws ParseException {
        String string = ConvertUtils.stringOrNull(bytes);
        for (FieldConvertInfo field: fields) {
            if (field.hyphenatedName.equals(string)) {
                return field;
            }
        }
        throw new ParseException("No field matching name found: " + string);
    }
}
