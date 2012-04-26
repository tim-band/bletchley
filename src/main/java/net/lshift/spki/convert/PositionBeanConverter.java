package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

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
    protected Map<Field, Object> readFields(final Converting c, final List<Sexp> tail)
        throws InvalidInputException {
        final int size = fields.size();
        if (tail.size() != size) {
            throw new ConvertException("Wrong number of fields");
        }
        final Map<Field, Object> res = new HashMap<Field, Object>(size);
        for (int i = 0; i < size; i++) {
            final FieldConvertInfo f = fields.get(i);
            res.put(f.field, readElement(f.field.getType(), c, tail.get(i)));
        }
        return res;
    }

    @Override
    protected Sexp writeField(
        final FieldConvertInfo field,
        final Object property) {
        return writeUnchecked(field.field.getType(), property);
    }
}
