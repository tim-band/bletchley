package net.lshift.spki.convert;

import java.util.List;

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
//        System.out.println("Fields for: " +  clazz.getCanonicalName());
//        for (FieldConvertInfo f: fields) {
//            System.out.println(f.hyphenatedName + " " + f.field.getType().getCanonicalName());
//        }
//        System.out.println("----------- " +  clazz.getCanonicalName());
    }

    @Override
    public void writeRest(final Converting c, final T o, final List<Sexp> out) {
        try {
            for (final FieldConvertInfo f: fields) {
                final Object property =
                    f.field.get(o);
                out.add(writeField(c, f, property));
            }
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(this, clazz, e);
        }
    }

    protected abstract Sexp writeField(
        Converting c,
        FieldConvertInfo fieldConvertInfo,
        Object property);
}
