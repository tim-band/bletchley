package net.lshift.spki.convert;

import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.convert.Convert.ConverterFactoryClass;

/**
 * Registry of SExp converters.  If a class implements the Convertible
 * interface, that means it knows how to convert itself and so doesn't
 * need to be registered in advance.
 */
public class Registry {
    public static final Registry REGISTRY = new Registry();

    protected Registry() {
        // Do nothing; this is here only to prevent anyone else creating one.
    }

    private final Map<Class<?>, Converter<?>> converterMap
        = new HashMap<Class<?>, Converter<?>>();

    private synchronized <T> void register(
        Class<T> clazz, Converter<T> converter) {
        Converter<?> already = converterMap.get(clazz);
        if (already != null) {
            assert already.equals(converter);
        } else {
            converterMap.put(clazz, converter);
        }
    }

    public static <T> void register(Converter<T> converter) {
        REGISTRY.register(converter.getResultClass(), converter);
    }

    static {
        register(new SexpConverter());
        register(new ByteArrayConverter());
        register(new StringConverter());
        register(new BigIntegerConverter());
        register(new DateConverter());
        register(new UUIDConverter());
    }

    @SuppressWarnings("unchecked")
    public synchronized <T> Converter<T> getConverter(Class<T> clazz) {
        Converter<T> res = (Converter<T>) converterMap.get(clazz);
        if (res == null) {
            try {
                final ConverterFactory factoryInstance
                    = getConverterFactory(clazz).value().newInstance();
                res = factoryInstance.converter(clazz);
                assert res.getResultClass().equals(clazz);
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

    private <T> ConverterFactoryClass getConverterFactory(
        Class<T> clazz) {
        ConverterFactoryClass factoryClass
            = clazz.getAnnotation(Convert.ConverterFactoryClass.class);
        if (factoryClass != null) {
            return factoryClass;
        }
        for (Annotation a: clazz.getAnnotations()) {
            factoryClass = a.annotationType().getAnnotation(
                Convert.ConverterFactoryClass.class);
            if (factoryClass != null) {
                return factoryClass;
            }
        }
        throw new ConvertReflectionException(clazz,
            "Could not resolve converter ");
    }
}
