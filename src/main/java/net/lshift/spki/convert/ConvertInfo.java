package net.lshift.spki.convert;

import static net.lshift.spki.Create.list;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.SExp;

public class ConvertInfo<T>
{
    private final String name;
    private final Constructor<T> constructor;
    private final List<Convertable> convertables;

    private ConvertInfo(String name, Constructor<T> constructor,
                       List<Convertable> convertables)
    {
        super();
        this.name = name;
        this.constructor = constructor;
        this.convertables = convertables;
    }

    private static Convertable getPositionalConvertable(
        int position, Class<?> class1,
        Annotation[] annotations)
    {
        for (Annotation a: annotations) {
            if (a instanceof P) {
                return new PositionConvertable(((P)a).value(), class1, position);
            }
        }
        throw new ConvertException("Constructor parameter not annotated");
    }

    private static <T> ConvertInfo<T> getPositionalConversion(
        String name,
        Constructor<T> constructor)
    {
        Class<?>[] parameters = constructor.getParameterTypes();
        Annotation[][] annotations = constructor.getParameterAnnotations();
        assert parameters.length == annotations.length;
        ArrayList<Convertable> convertables = new ArrayList<Convertable>(
                        parameters.length);
        for (int i = 0; i < parameters.length; i++) {
            convertables.add(getPositionalConvertable(i+1, parameters[i], annotations[i]));
        }
        return new ConvertInfo<T>(name, constructor, convertables);
    }

    private static Convertable getDictlikeConvertable(
        Class<?> class1,
        Annotation[] annotations)
    {
        for (Annotation a: annotations) {
            if (a instanceof P) {
                return new NameConvertable(((P)a).value(), class1);
            }
        }
        throw new ConvertException("Constructor parameter not annotated");
    }

    private static <T> ConvertInfo<T> getDictlikeConversion(
        String name,
        Constructor<T> constructor)
    {
        Class<?>[] parameters = constructor.getParameterTypes();
        Annotation[][] annotations = constructor.getParameterAnnotations();
        assert parameters.length == annotations.length;
        ArrayList<Convertable> convertables = new ArrayList<Convertable>(
                        parameters.length);
        for (int i = 0; i < parameters.length; i++) {
            convertables.add(getDictlikeConvertable(parameters[i], annotations[i]));
        }
        return new ConvertInfo<T>(name, constructor, convertables);
    }

    @SuppressWarnings("unchecked")
    public static <T> ConvertInfo<T> getConversion(Class<T> class1) {
        for (Constructor<?> c: class1.getConstructors()) {
            DictlikeSexp ds = c.getAnnotation(DictlikeSexp.class);
            if (ds != null) {
                return getDictlikeConversion(ds.value(), (Constructor<T>) c);
            }
            PositionalSexp ps = c.getAnnotation(PositionalSexp.class);
            if (ps != null) {
                return getPositionalConversion(ps.value(), (Constructor<T>) c);
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
        for (Convertable c: convertables) {
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
