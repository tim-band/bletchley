package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

public class PositionSequenceConverter<T>
    extends BeanConverter<T> {
    private final List<FieldConvertInfo> fields;
    private final Field seq;
    private final Class<?> contentType;

    public PositionSequenceConverter(final Class<T> clazz, final String name,
                                     final List<FieldConvertInfo> fields, final Field seq) {
        super(clazz, name);
        this.fields = fields;
        this.seq = seq;
        contentType = SequenceConverter.getTypeInList(clazz, seq);
    }

    @Override
    public void writeRest(final Converting c, final T o, final List<Sexp> tail) {
        try {
            for (final FieldConvertInfo f: fields) {
                tail.add(c.writeUnchecked(f.field.getType(), f.field.get(o)));
            }
            final List<?> property = (List<?>) seq.get(o);
            for (final Object v: property) {
                tail.add(c.writeUnchecked(contentType, v));
            }
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(this, clazz, e);
        }
    }

    @Override
    protected Map<Field, Object> readFields(final Converting c, final List<Sexp> tail)
        throws InvalidInputException {
        final int size = fields.size();
        final Map<Field, Object> rmap = new HashMap<Field, Object>(size + 1);
        for (int i = 0; i < size; i++) {
            final FieldConvertInfo f = fields.get(i);
            rmap.put(f.field, c.read(f.field.getType(), tail.get(i)));
        }
        rmap.put(seq, SequenceConverter.readSequence(c, contentType,
            tail.subList(size, tail.size())));
        return rmap;
    }
}
