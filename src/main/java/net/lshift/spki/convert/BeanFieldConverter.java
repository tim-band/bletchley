package net.lshift.spki.convert;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import net.lshift.spki.ParseException;

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
    public void write(final ConvertOutputStream out, final T o)
        throws IOException {
        try {
            out.beginSexp();
            writeName(out);
            for (final FieldConvertInfo f: fields) {
                final Object property =
                    f.field.get(o);
                writeField(out, f, property);
            }
            out.endSexp();
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(this, clazz, e);
        }
    }

    protected abstract void writeField(
        ConvertOutputStream out,
        FieldConvertInfo fieldConvertInfo,
        Object property) throws IOException;

    @Override
    public T read(final ConvertInputStream in)
        throws ParseException,
            IOException {
        try {
            return DeserializingConstructor.make(clazz, readFields(in));
        } catch (final InstantiationException e) {
            throw new ConvertReflectionException(e);
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(e);
        } catch (final SecurityException e) {
            throw new ConvertReflectionException(e);
        } catch (final IllegalArgumentException e) {
            throw new ConvertReflectionException(e);
        }
    }

    protected abstract Map<Field, Object> readFields(ConvertInputStream in)
        throws ParseException,
            IOException;
}
