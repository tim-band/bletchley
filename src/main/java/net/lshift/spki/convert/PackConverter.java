package net.lshift.spki.convert;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import net.lshift.spki.Sexp;

/**
 * "Pack" protocol converter - convert to sexp via another object and
 * "pack" or "unpack" methods.
 */
public class PackConverter<T extends PackConvertible>
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
    public T fromSexp(Sexp sexp)
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
    public void write(ConvertOutputStream out, T o)
        throws IOException
    {
        out.writeUnchecked(otherType, o.pack());
    }
}
