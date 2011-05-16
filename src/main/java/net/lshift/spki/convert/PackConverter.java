package net.lshift.spki.convert;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import net.lshift.spki.SExp;

public class PackConverter<T extends PackConvertable>
    implements Converter<T>
{
    private final Method packMethod;
    private final Method unpackMethod;
    private final Class<?> otherType;

    public PackConverter(Class<T> clazz)
    {
        try {
            packMethod = clazz.getMethod("pack");
            otherType = packMethod.getReturnType();
            unpackMethod = clazz.getMethod("unpack", otherType);
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
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
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public SExp toSexp(T o)
    {
        return Convert.toSExpUnchecked(otherType, o.pack());
    }
}
