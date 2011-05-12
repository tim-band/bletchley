package net.lshift.spki.convert;

import static net.lshift.spki.Create.list;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.SExp;

public class ClassConvertInfo<T>
{
    private final String name;
    private final Constructor<T> constructor;
    private final List<FieldConvertInfo> fields;

    private ClassConvertInfo(String name, Constructor<T> constructor,
                       List<FieldConvertInfo> fields)
    {
        super();
        this.name = name;
        this.constructor = constructor;
        this.fields = fields;
    }

    private static FieldConvertInfo getPositionalFieldConvertInfo(
        int position, Class<?> class1,
        Annotation[] annotations)
    {
        for (Annotation a: annotations) {
            if (a instanceof P) {
                return new PositionFieldConvertInfo(((P)a).value(), class1, position);
            }
        }
        throw new ConvertException("Constructor parameter not annotated");
    }

    private static <T> ClassConvertInfo<T> getPositionalClassConvertInfo(
        String name,
        Constructor<T> constructor)
    {
        Class<?>[] parameters = constructor.getParameterTypes();
        Annotation[][] annotations = constructor.getParameterAnnotations();
        assert parameters.length == annotations.length;
        ArrayList<FieldConvertInfo> fields = new ArrayList<FieldConvertInfo>(
                        parameters.length);
        for (int i = 0; i < parameters.length; i++) {
            fields.add(getPositionalFieldConvertInfo(i+1, parameters[i], annotations[i]));
        }
        return new ClassConvertInfo<T>(name, constructor, fields);
    }

    private static FieldConvertInfo getDictlikeFieldConvertInfo(
        Class<?> class1,
        Annotation[] annotations)
    {
        for (Annotation a: annotations) {
            if (a instanceof P) {
                return new NameFieldConvertInfo(((P)a).value(), class1);
            }
        }
        throw new ConvertException("Constructor parameter not annotated");
    }

    private static <T> ClassConvertInfo<T> getDictlikeClassConvertInfo(
        String name,
        Constructor<T> constructor)
    {
        Class<?>[] parameters = constructor.getParameterTypes();
        Annotation[][] annotations = constructor.getParameterAnnotations();
        assert parameters.length == annotations.length;
        ArrayList<FieldConvertInfo> fields = new ArrayList<FieldConvertInfo>(
                        parameters.length);
        for (int i = 0; i < parameters.length; i++) {
            fields.add(getDictlikeFieldConvertInfo(parameters[i], annotations[i]));
        }
        return new ClassConvertInfo<T>(name, constructor, fields);
    }

    @SuppressWarnings("unchecked")
    public static <T> ClassConvertInfo<T> getClassConvertInfo(Class<T> class1) {
        for (Constructor<?> c: class1.getConstructors()) {
            DictlikeSexp ds = c.getAnnotation(DictlikeSexp.class);
            if (ds != null) {
                return getDictlikeClassConvertInfo(ds.value(), (Constructor<T>) c);
            }
            PositionalSexp ps = c.getAnnotation(PositionalSexp.class);
            if (ps != null) {
                return getPositionalClassConvertInfo(ps.value(), (Constructor<T>) c);
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
        for (FieldConvertInfo c: fields) {
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
        Object[] initargs = new Object[fields.size()];
        for (int i = 0; i < initargs.length; i++) {
            initargs[i] = fields.get(i).getValue(sexp);
        }
        return constructor.newInstance(initargs);
    }
}
