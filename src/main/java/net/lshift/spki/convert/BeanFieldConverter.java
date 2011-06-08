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

    public BeanFieldConverter(Class<T> clazz, String name, List<FieldConvertInfo> fields)
    {
        super(clazz, name);
        this.fields = fields;
    }

    @Override
    public void write(ConvertOutputStream out, T o)
        throws IOException {
        try {
            out.beginSexp();
            writeName(out);
            for (FieldConvertInfo f: fields) {
                final Object property =
                    f.field.get(o);
                writeField(out, f, property);
            }
            out.endSexp();
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(this, clazz, e);
        }
    }

    protected abstract void writeField(
        ConvertOutputStream out,
        FieldConvertInfo fieldConvertInfo,
        Object property) throws IOException;

    @Override
    public T read(ConvertInputStream in)
        throws ParseException,
            IOException {
        try {
            return DeserializingConstructor.make(clazz, readFields(in));
        } catch (InstantiationException e) {
            throw new ConvertReflectionException(e);
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(e);
        } catch (SecurityException e) {
            throw new ConvertReflectionException(e);
        } catch (IllegalArgumentException e) {
            throw new ConvertReflectionException(e);
        }
    }

    protected abstract Map<Field, Object> readFields(ConvertInputStream in)
        throws ParseException,
            IOException;
}
