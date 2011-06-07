package net.lshift.spki.convert;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import net.lshift.spki.convert.Convert.ConverterFactoryClass;
import net.lshift.spki.sexpform.Sexp;

/**
 * Registry of SExp converters.  If a class implements the Convertible
 * interface, that means it knows how to convert itself and so doesn't
 * need to be registered in advance.
 */
public class Registry {
    public static final Registry REGISTRY = new Registry();

    private final Map<Class<?>, Converter<?>> converterMap
        = new HashMap<Class<?>, Converter<?>>();

    public synchronized <T> void register(Class<T> clazz, Converter<T> converter) {
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
        register(UUID.class, new UUIDConverter());
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
                ConverterFactoryClass factoryClass = clazz.getAnnotation(Convert.ConverterFactoryClass.class);
                for(Annotation a: clazz.getAnnotations()) {
                        if(factoryClass != null) break;
                        factoryClass = a.getClass().getAnnotation(Convert.ConverterFactoryClass.class);
                }

                if(factoryClass != null) {
                    ConverterFactory factory = factoryClass.value().newInstance();
                    res = factory.converter(clazz);
                }
                else {
                    throw new ConvertReflectionException("Could not resolve converter for " + clazz.getName());
                }

            } catch (SecurityException e) {
                throw new ConvertReflectionException(e);
            } catch (IllegalArgumentException e) {
                throw new ConvertReflectionException(e);
            } catch (IllegalAccessException e) {
                throw new ConvertReflectionException(e);
            } catch (InstantiationException e) {
                throw new ConvertReflectionException(e);
            }

            converterMap.put(clazz, res);
        }
        return res;
    }
}
