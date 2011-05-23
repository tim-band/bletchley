package net.lshift.spki.convert;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.Sexp;

/**
 * Registry of SExp converters.  If a class implements the Convertible
 * interface, that means it knows how to convert itself and so doesn't
 * need to be registered in advance.
 */
public class Registry
{
    public static final Registry REGISTRY = new Registry();

    private final Map<Class<?>, Converter<?>> converterMap
        = new HashMap<Class<?>, Converter<?>>();

    public synchronized <T> void register(
        Class<T> clazz,
        Converter<T> converter)
    {
        Converter<?> already = converterMap.get(clazz);
        if (already != null) {
            assert already.equals(converter);
        } else {
            converterMap.put(clazz, converter);
        }
    }

    {
        register(Sexp.class, new SexpConverter());
        register(byte[].class, new ByteArrayConverter());
        register(String.class, new StringConverter());
        register(BigInteger.class, new BigIntegerConverter());
        register(Date.class, new DateConverter());
    }

    @SuppressWarnings("unchecked")
    public synchronized <T> Converter<T> getConverter(Class<T> clazz) {
        Converter<T> res = (Converter<T>) converterMap.get(clazz);
        if (res == null) {
            if (!Convertible.class.isAssignableFrom(clazz)) {
                throw new ConvertException("Don't know how to serialize class:"
                    + clazz.getCanonicalName());
            }
            try {
                // Should be a static method
                res = (Converter<T>) clazz.getMethod(
                    "getConverter", Class.class).invoke(null, clazz);
            } catch (SecurityException e) {
                throw new ConvertReflectionException(e);
            } catch (NoSuchMethodException e) {
                throw new ConvertReflectionException(e);
            } catch (IllegalArgumentException e) {
                throw new ConvertReflectionException(e);
            } catch (IllegalAccessException e) {
                throw new ConvertReflectionException(e);
            } catch (InvocationTargetException e) {
                throw new ConvertReflectionException(e);
            }
            converterMap.put(clazz, res);
        }
        return res;
    }
}
