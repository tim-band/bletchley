package net.lshift.spki.convert;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * SExp converter that lists the bean fields in a fixed order.
 */
public class PositionBeanConverter<T>
    extends BeanFieldConverter<T> {
    public PositionBeanConverter(
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
        out.writeUnchecked(field.field.getType(), property);
    }

    @Override
    protected Map<Field, Object> readFields(final ConvertInputStream in)
        throws ParseException,
            IOException {
        final Map<Field, Object> res = new HashMap<Field, Object>(fields.size());
        in.nextAssertType(TokenType.OPENPAREN);
        in.assertAtom(name);
        for (final FieldConvertInfo f: fields) {
            res.put(f.field, in.read(f.field.getType()));
        }
        in.nextAssertType(TokenType.CLOSEPAREN);
        return res;
    }
}
