package net.lshift.spki.convert;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;

public class PositionSequenceConverter<T>
    extends BeanConverter<T> {
    private final List<FieldConvertInfo> fields;
    private final Field seq;
    private Class<?> contentType;

    public PositionSequenceConverter(Class<T> clazz, String name,
                                     List<FieldConvertInfo> fields, Field seq) {
        super(clazz, name);
        this.fields = fields;
        this.seq = seq;
        contentType = SequenceConverter.getTypeInList(clazz, seq);
    }

    @Override
    public void write(ConvertOutputStream out, T o)
        throws IOException {
        try {
            out.beginSexp();
            writeName(out);
            for (final FieldConvertInfo f: fields) {
                out.writeUnchecked(f.field.getType(), f.field.get(o));
            }
            final List<?> property = (List<?>) seq.get(o);
            for (final Object v: property) {
                out.writeUnchecked(contentType, v);
            }
            out.endSexp();
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(this, clazz, e);
        }
    }

    @Override
    public T readRest(ConvertInputStream in)
        throws IOException,
            InvalidInputException {
        final Map<Field, Object> rmap = new HashMap<Field, Object>(fields.size());
        for (final FieldConvertInfo f: fields) {
            rmap.put(f.field, in.read(f.field.getType()));
        }
        rmap.put(seq, SequenceConverter.readSequence(contentType, in));
        return DeserializingConstructor.convertMake(clazz, rmap);
    }
}
