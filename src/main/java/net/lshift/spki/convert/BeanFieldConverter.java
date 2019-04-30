package net.lshift.spki.convert;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.lshift.spki.sexpform.Sexp;

/**
 * Superclass for a converter that reads bean properties based on
 * an annotated constructor.
 */
public abstract class BeanFieldConverter<T>
    extends BeanConverter<T> {

    protected final List<FieldConvertInfo> fields;

    public BeanFieldConverter(final Class<T> clazz, final String name, final List<FieldConvertInfo> fields)
    {
        super(clazz, name);
        this.fields = fields;
    }

    @Override
    public void writeRest(final T o, final List<Sexp> out) {
        try {
            for (final FieldConvertInfo f: fields) {
                final Object property =
                    f.field.get(o);
                final Sexp sexp = writeField(f, property);
                if (sexp != null)
                    out.add(sexp);
            }
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(this, clazz, e);
        }
    }

    protected abstract Sexp writeField(
        FieldConvertInfo fieldConvertInfo,
        Object property);

    public static Set<Class<?>> references(
            List<FieldConvertInfo> fields,
            Set<Class<?>> exclude) {
        Set<Class<?>> refs = new HashSet<>(fields.size());
        for(FieldConvertInfo info: fields) {
            Class<?> type = (info.inlineListType != null)
                    ? info.inlineListType
                    : info.field.getType();
            if(!exclude.contains(type))
                refs.add(type);
        }
        return refs;
    }
}
