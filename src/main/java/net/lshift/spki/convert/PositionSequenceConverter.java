package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.schema.ConverterDeclaration;
import net.lshift.spki.schema.VariadicType;
import net.lshift.spki.schema.TypeReference;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.sexpform.Slist;

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
    public void writeRest(final T o, final List<Sexp> tail) {
        try {
            for (final FieldConvertInfo f: fields) {
                tail.add(writeUnchecked(f.field.getType(), f.field.get(o)));
            }
            final List<?> property = (List<?>) seq.get(o);
            for (final Object v: property) {
                tail.add(writeUnchecked(contentType, v));
            }
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(this, clazz, e);
        }
    }

    @Override
    protected Map<Field, Object> readFields(final ConverterCatalog c, final Slist tail)
        throws InvalidInputException {
        final int size = fields.size();
        final Map<Field, Object> rmap = SexpBacked.getResMap(tail);
        for (int i = 0; i < size; i++) {
            final FieldConvertInfo f = fields.get(i);
            rmap.put(f.field, readElement(f.field.getType(), c, tail.getSparts().get(i)));
        }
        rmap.put(seq, readSequence(c, contentType,
            tail.getSparts().subList(size, tail.getSparts().size())));
        return rmap;
    }

    @Override
    public ConverterDeclaration declaration() {
        return new VariadicType(
                BeanFieldConverter.fieldDeclarations(fields), 
                new TypeReference(contentType));
    }

    @Override
    public Set<Class<?>> references() {
        Set<Class<?>> refs = BeanFieldConverter.references(fields, excludeReferences());
        refs.add(contentType);
        return Collections.unmodifiableSet(refs);
    }
}
