package net.lshift.spki.convert;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import org.apache.commons.beanutils.PropertyUtils;

import net.lshift.spki.Create;
import net.lshift.spki.SExp;
import net.lshift.spki.SList;

public abstract class BeanConverter<T> implements Converter<T>
{
    private final String name;
    private final Constructor<T> constructor;
    private final FieldConvertInfo[] fields;

    @SuppressWarnings("unchecked")
    public BeanConverter(Class<T> clazz)
    {
        for (Constructor<?> c: clazz.getConstructors()) {
            SExpName sname = c.getAnnotation(SExpName.class);
            if (sname != null) {
                name = sname.value();
                constructor = (Constructor<T>) c;
                Class<?>[] parameters = c.getParameterTypes();
                Annotation[][] annotations = c.getParameterAnnotations();
                assert parameters.length == annotations.length;
                fields = new FieldConvertInfo[parameters.length];
                for (int i = 0; i < parameters.length; i++) {
                    fields[i] = new FieldConvertInfo(
                        getName(annotations[i]), parameters[i]);
                }
                return;
            }
        }
        throw new RuntimeException("No suitably annotated constructor: " +
                        clazz.getCanonicalName());
    }

    private String getName(Annotation[] annotations)
    {
        for (Annotation a: annotations) {
            if (a instanceof P) {
                return ((P)a).value();
            }
        }
        throw new RuntimeException("No P annotation found");
    }

    @Override
    public SExp toSexp(T o)
    {
        try {
            SExp[] components = new SExp[fields.length];
            for (int i = 0; i < fields.length; i++) {
                final Object property = PropertyUtils.getProperty(o,
                    fields[i].getName());
                components[i] = fieldToSexp(fields[i],
                    Convert.toSExpUnchecked((Class<?>) fields[i].getType(), property));
            }
            return Create.list(name, components);
        } catch (IllegalAccessException e) {
            // TODO Auto-generated catch block
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            // TODO Auto-generated catch block
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e) {
            // TODO Auto-generated catch block
            throw new RuntimeException(e);
        }
    }

    protected abstract SExp fieldToSexp(
        FieldConvertInfo fieldConvertInfo,
        SExp sexp);

    @Override
    public T fromSexp(SExp sexp)
    {
        SList slist = (SList) sexp;
        if (!Create.atom(name).equals(slist.getHead())) {
            throw new ConvertException("Expected " + name +
                " but was " + slist.getHead());
        }
        Object[] initargs = new Object[fields.length];
        for (int i = 0; i < fields.length; i++) {
            initargs[i] = Convert.fromSExp(fields[i].getType(),
                getSExp(fields[i], i, slist));
        }
        try {
            return constructor.newInstance(initargs);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    protected abstract SExp getSExp(
        FieldConvertInfo fieldConvertInfo,
        int i,
        SList slist);
}
