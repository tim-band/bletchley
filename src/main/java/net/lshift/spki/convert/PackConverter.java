package net.lshift.spki.convert;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import net.lshift.spki.SExp;

/**
 * "Pack" protocol converter - convert to sexp via another object and
 * "pack" or "unpack" methods.
 */
public class PackConverter<T extends PackConvertable>
    implements Converter<T>
{
    private final Method unpackMethod;
    private final Class<?> otherType;

    public PackConverter(Class<T> clazz)
    {
        try {
            otherType = clazz.getMethod("pack").getReturnType();
            unpackMethod = clazz.getMethod("unpack", otherType);
        } catch (SecurityException e) {
            throw new ConvertReflectionException(e);
        } catch (NoSuchMethodException e) {
            throw new ConvertReflectionException(e);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public T fromSexp(SExp sexp)
    {
        try {
            return (T) unpackMethod.invoke(null,
                Convert.fromSExp(otherType, sexp));
        } catch (IllegalArgumentException e) {
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
        return Convert.toSExpUnchecked(otherType, o.pack());
    }
}