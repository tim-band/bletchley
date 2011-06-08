package net.lshift.spki.convert;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;

import net.lshift.spki.ParseException;

/**
 * Superclass for a converter that reads bean properties based on
 * an annotated constructor.
 */
public abstract class BeanFieldConverter<T>
    extends BeanConverter<T> {
    protected final FieldConvertInfo[] fields;

    public BeanFieldConverter(Class<T> clazz)
    {
        super(clazz);
        Class<?>[] parameters = constructor.getParameterTypes();
        Annotation[][] annotations = constructor.getParameterAnnotations();
        assert parameters.length == annotations.length;
        fields = new FieldConvertInfo[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            try {
                fields[i] = new FieldConvertInfo(clazz, i,
                    getPAnnotation(annotations[i]), parameters[i]);
            } catch (SecurityException e) {
                throw new ConvertReflectionException(this, clazz, e);
            } catch (NoSuchFieldException e) {
                throw new ConvertReflectionException(this, clazz, e);
            }
        }
    }

    @Override
    public void write(ConvertOutputStream out, T o)
        throws IOException {
        try {
            out.beginSexp();
            writeName(out);
            for (int i = 0; i < fields.length; i++) {
                final Object property =
                    fields[i].field.get(o);
                writeField(out, fields[i], property);
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
        Object[] initargs = new Object[fields.length];
        read(in, initargs);
        try {
            return constructor.newInstance(initargs);
        } catch (InstantiationException e) {
            throw new ConvertReflectionException(e);
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(e);
        } catch (InvocationTargetException e) {
            throw new ConvertReflectionException(e);
        }
    }

    protected abstract void read(ConvertInputStream in, Object[] initargs)
        throws ParseException,
            IOException;
}
