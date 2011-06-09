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
    private static final Registry REGISTRY = new Registry();

    protected Registry() {
        // Do nothing; this is here only to prevent anyone else creating one.
    }

    private final Map<Class<?>, Converter<?>> converterMap
        = new HashMap<Class<?>, Converter<?>>();

    private synchronized <T> void register(
        final Class<T> clazz, final Converter<T> converter) {
        final Converter<?> already = converterMap.get(clazz);
        if (already != null) {
            assert already.equals(converter);
        } else {
            converterMap.put(clazz, converter);
        }
    }

    public static <T> void register(final Converter<T> converter) {
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

    public static <T> Converter<T> getConverter(final Class<T> clazz) {
        return REGISTRY.getConverterInternal(clazz);
    }

    @SuppressWarnings("unchecked")
    private synchronized <T> Converter<T> getConverterInternal(
        final Class<T> clazz) {
        Converter<T> res = (Converter<T>) converterMap.get(clazz);
        if (res == null) {
            res = generateConverter(clazz);
            converterMap.put(clazz, res);
        }
        return res;
    }

    private <T> Converter<T> generateConverter(final Class<T> clazz) {
        try {
            for (final Annotation a : clazz.getAnnotations()) {
                final ConverterFactoryClass factoryClass
                    = a.annotationType().getAnnotation(
                        Convert.ConverterFactoryClass.class);
                if (factoryClass != null) {
                    // FIXME: cache these?
                    final ConverterFactory factoryInstance
                        = factoryClass.value().newInstance();
                    final Converter<T> res = factoryInstance.converter(clazz, a);
                    if (!res.getResultClass().equals(clazz)) {
                        throw new ConvertReflectionException(clazz,
                            "Didn't get appropriate converter!");
                    }
                    return res;
                }
            }
            throw new ConvertReflectionException(clazz,
                            "Could not resolve converter");
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(clazz, e);
        } catch (final InstantiationException e) {
            throw new ConvertReflectionException(clazz, e);
        }
    }
}
