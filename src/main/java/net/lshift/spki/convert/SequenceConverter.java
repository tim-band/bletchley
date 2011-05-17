package net.lshift.spki.convert;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.Create;
import net.lshift.spki.SExp;
import net.lshift.spki.SList;

import org.apache.commons.beanutils.PropertyUtils;

/**
 * Converter for a class that has a single field of type List.
 */
public class SequenceConverter<T> extends BeanConverter<T>
{
    private final String beanName;
    private final Class<?> contentType;

    public SequenceConverter(Class<T> clazz)
    {
        super(clazz);
        Annotation[][] annotations = constructor.getParameterAnnotations();
        if (annotations.length != 1) {
            throw new ConvertException(
                "Constructor must be one argument:"
                + clazz.getCanonicalName());
        }
        beanName = getPAnnotation(annotations[0]);
        Type[] pTypes = constructor.getGenericParameterTypes();
        if (!(pTypes[0] instanceof ParameterizedType)) {
            throw new ConvertException(
                "Constructor argument must be parameterized List type:"
                + clazz.getCanonicalName());
        }
        ParameterizedType pType = (ParameterizedType) pTypes[0];
        if (!List.class.equals(pType.getRawType())) {
            throw new ConvertException(
                "Constructor argument must be List type:"
                + clazz.getCanonicalName());
        }
        Type[] typeArgs = pType.getActualTypeArguments();
        if (typeArgs.length != 1) {
            throw new ConvertException(
                "Constructor type must have one parameter"
                + clazz.getCanonicalName());
        }
        contentType = (Class<?>) typeArgs[0];
    }

    @Override
    public T fromSexp(SExp sexp)
    {
        SList slist = (SList) sexp;
        if (!Create.atom(name).equals(slist.getHead())) {
            throw new ConvertException("Expected " + name +
                " but was " + slist.getHead());
        }
        SExp[] tail = slist.getSparts();
        List<Object> components = new ArrayList<Object>(tail.length);
        for (int i = 0; i < tail.length; i++) {
            components.add(Convert.fromSExp(contentType, tail[i]));
        }
        Object[] initargs = new Object[1];
        initargs[0] = components;
        try {
            return constructor.newInstance(initargs);
        } catch (IllegalArgumentException e) {
            throw new ConvertReflectionException(e);
        } catch (InstantiationException e) {
            throw new ConvertReflectionException(e);
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(e);
        } catch (InvocationTargetException e) {
            throw new ConvertReflectionException(e);
        }
    }

    @Override
    public SExp toSexp(T o)
    {
        try {
            List<?> property = (List<?>) PropertyUtils.getProperty(o,
                beanName);
            List<SExp> components = new ArrayList<SExp>(property.size());
            for (Object v: property) {
                components.add(Convert.toSExpUnchecked(contentType, v));
            }
            return Create.list(name, components);
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(e);
        } catch (InvocationTargetException e) {
            throw new ConvertReflectionException(e);
        } catch (NoSuchMethodException e) {
            throw new ConvertReflectionException(e);
        }
    }

}
