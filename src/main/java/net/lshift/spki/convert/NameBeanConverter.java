package net.lshift.spki.convert;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * SExp converter that produces a SExp that looks like key-value pairs
 */
public class NameBeanConverter<T>
    extends BeanFieldConverter<T> {
    public NameBeanConverter(
        final Class<T> clazz,
        final String name,
        final List<FieldConvertInfo> fields) {
        super(clazz, name, fields);
    }

    @Override
    protected void writeField(
        final ConvertOutputStream out,
        final FieldConvertInfo field,
        final Object property)
        throws IOException {
        if (property != null) {
            out.beginSexp();
            out.atom(field.hyphenatedName);
            out.writeUnchecked(field.field.getType(), property);
            out.endSexp();
        } else if (!field.nullable) {
            throw new NullPointerException(
                "Field not marked as nullable is null: " +
                clazz.getCanonicalName() + "." + field.name);
        }
        // else ignore it - write nothing, report nothing
    }

    @Override
    protected Map<Field, Object> readFields(final ConvertInputStream in)
        throws InvalidInputException,
            IOException {
        final Map<Field, Object> res = new HashMap<Field, Object>();
        while (in.peek() == TokenType.OPENPAREN) {
            in.next();
            in.nextAssertType(TokenType.ATOM);
            final FieldConvertInfo field = getField(in.atomBytes());
            if (res.containsKey(field.field)) {
                throw new ConvertException("Repeated field");
            }
            res.put(field.field, in.read(field.field.getType()));
            in.nextAssertType(TokenType.CLOSEPAREN);
        }
        in.nextAssertType(TokenType.CLOSEPAREN);
        for (final FieldConvertInfo field: fields) {
            if (!field.nullable && !res.containsKey(field.field)) {
                throw new ConvertException("Missing field: " + field.hyphenatedName);
            }
        }
        return res;
    }

    private FieldConvertInfo getField(final byte[] bytes)
        throws ConvertException {
        final String string = ConvertUtils.stringOrNull(bytes);
        for (final FieldConvertInfo field: fields) {
            if (field.hyphenatedName.equals(string)) {
                return field;
            }
        }
        throw new ConvertException("No field matching name found: " + string);
    }
}
