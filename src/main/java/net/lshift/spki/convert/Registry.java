package net.lshift.spki.convert;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.SExp;

public class Registry
{
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
        final SExpConverter sexpConverter = new SExpConverter();
        register(SExp.class, sexpConverter);
        register(byte[].class, new ByteArrayConverter());
        register(String.class, new StringConverter());
        register(BigInteger.class, new BigIntegerConverter());
        register(Date.class, new DateConverter());
    }

    @SuppressWarnings("unchecked")
    public synchronized <T> Converter<T> getConverter(Class<T> clazz) {
        Converter<T> res = (Converter<T>) converterMap.get(clazz);
        if (res == null) {
            if (!Convertable.class.isAssignableFrom(clazz)) {
                throw new RuntimeException("Don't know how to serialize class:"
                    + clazz.getCanonicalName());
            }
            try {
                // Should be a static method
                res = (Converter<T>) clazz.getMethod(
                    "getConverter", Class.class).invoke(null, clazz);
            } catch (SecurityException e) {
                throw new RuntimeException(e);
            } catch (NoSuchMethodException e) {
                throw new RuntimeException(e);
            } catch (IllegalArgumentException e) {
                throw new RuntimeException(e);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            } catch (InvocationTargetException e) {
                throw new RuntimeException(e);
            }
            converterMap.put(clazz, res);
        }
        return res;
    }
}
