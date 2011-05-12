package net.lshift.spki.convert;

import static net.lshift.spki.Create.list;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.SExp;

public class FieldConvertInfo<T>
{
    private final String name;
    private final Constructor<T> constructor;
    private final List<ClassConvertInfo> convertables;

    private FieldConvertInfo(String name, Constructor<T> constructor,
                       List<ClassConvertInfo> convertables)
    {
        super();
        this.name = name;
        this.constructor = constructor;
        this.convertables = convertables;
    }

    private static ClassConvertInfo getPositionalClassConvertInfo(
        int position, Class<?> class1,
        Annotation[] annotations)
    {
        for (Annotation a: annotations) {
            if (a instanceof P) {
                return new PositionClassConvertInfo(((P)a).value(), class1, position);
            }
        }
        throw new ConvertException("Constructor parameter not annotated");
    }

    private static <T> FieldConvertInfo<T> getPositionalFieldConvertInfo(
        String name,
        Constructor<T> constructor)
    {
        Class<?>[] parameters = constructor.getParameterTypes();
        Annotation[][] annotations = constructor.getParameterAnnotations();
        assert parameters.length == annotations.length;
        ArrayList<ClassConvertInfo> convertables = new ArrayList<ClassConvertInfo>(
                        parameters.length);
        for (int i = 0; i < parameters.length; i++) {
            convertables.add(getPositionalClassConvertInfo(i+1, parameters[i], annotations[i]));
        }
        return new FieldConvertInfo<T>(name, constructor, convertables);
    }

    private static ClassConvertInfo getDictlikeClassConvertInfo(
        Class<?> class1,
        Annotation[] annotations)
    {
        for (Annotation a: annotations) {
            if (a instanceof P) {
                return new NameClassConvertInfo(((P)a).value(), class1);
            }
        }
        throw new ConvertException("Constructor parameter not annotated");
    }

    private static <T> FieldConvertInfo<T> getDictlikeFieldConvertInfo(
        String name,
        Constructor<T> constructor)
    {
        Class<?>[] parameters = constructor.getParameterTypes();
        Annotation[][] annotations = constructor.getParameterAnnotations();
        assert parameters.length == annotations.length;
        ArrayList<ClassConvertInfo> convertables = new ArrayList<ClassConvertInfo>(
                        parameters.length);
        for (int i = 0; i < parameters.length; i++) {
            convertables.add(getDictlikeClassConvertInfo(parameters[i], annotations[i]));
        }
        return new FieldConvertInfo<T>(name, constructor, convertables);
    }

    @SuppressWarnings("unchecked")
    public static <T> FieldConvertInfo<T> getFieldConvertInfo(Class<T> class1) {
        for (Constructor<?> c: class1.getConstructors()) {
            DictlikeSexp ds = c.getAnnotation(DictlikeSexp.class);
            if (ds != null) {
                return getDictlikeFieldConvertInfo(ds.value(), (Constructor<T>) c);
            }
            PositionalSexp ps = c.getAnnotation(PositionalSexp.class);
            if (ps != null) {
                return getPositionalFieldConvertInfo(ps.value(), (Constructor<T>) c);
            }
        }
        throw new ConvertException("No suitably annotated constructor");
    }

    public SExp toSExp(T bean)
        throws IllegalAccessException,
            InvocationTargetException,
            NoSuchMethodException
    {
        List<SExp> values = new ArrayList<SExp>();
        for (ClassConvertInfo c: convertables) {
            values.add(c.genSexp(bean));
        }
        return list(name, values);
    }

    @SuppressWarnings("unchecked")
    public SExp toSExpCast(Object bean)
        throws IllegalAccessException,
            InvocationTargetException,
            NoSuchMethodException
    {
        return toSExp((T) bean);
    }

    public T fromSExp(SExp sexp)
        throws IllegalArgumentException,
            InstantiationException,
            IllegalAccessException,
            InvocationTargetException
    {
        Object[] initargs = new Object[convertables.size()];
        for (int i = 0; i < initargs.length; i++) {
            initargs[i] = convertables.get(i).getValue(sexp);
        }
        return constructor.newInstance(initargs);
    }
}
