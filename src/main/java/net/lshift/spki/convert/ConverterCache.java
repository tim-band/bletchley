package net.lshift.spki.convert;

import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.convert.Convert.ConverterFactoryClass;
import net.lshift.spki.convert.Convert.HandlerClass;

/**
 * Registry of class -> converter map.  With the exception of a fixed list
 * of converters initialized at startup, this contains only those converters
 * that a class defines for itself based on annotations.  Foreign conversions
 * must be registered with the containing converter.
 */
public class ConverterCache {
    private static final ConverterCache GLOBAL_CACHE = new ConverterCache();

    private final Map<Class<?>, ConverterFactory<?>> factoryCache
        = new HashMap<Class<?>, ConverterFactory<?>>();

    private final Map<Class<?>, Converter<?>> converterMap
        = new HashMap<Class<?>, Converter<?>>();

    private ConverterCache() {
        registerInternal(new ByteArrayConverter());
        registerInternal(new StringConverter());
        registerInternal(new BigIntegerConverter());
        registerInternal(new IntegerConverter());
        registerInternal(new DateConverter());
        registerInternal(new URIConverter());
        registerInternal(new URLConverter());
        registerInternal(new UUIDConverter());
    }

    private <T> void registerInternal(final Converter<T> converter) {
        converterMap.put(converter.getResultClass(), converter);
    }

    public static <T> Converter<T> getConverter(final Class<T> clazz) {
        return GLOBAL_CACHE.getConverterInternal(clazz);
    }

    @SuppressWarnings("unchecked")
    private synchronized <T> Converter<T> getConverterInternal(
        final Class<T> clazz) {
        Converter<T> res = (Converter<T>) converterMap.get(clazz);
        if (res == null) {
            res = generateConverter(clazz);
            converterMap.put(clazz, res);
            boolean success = false;
            try {
                handleAnnotations(clazz, res);
                success = true;
            } finally {
                if (!success) {
                    converterMap.remove(clazz);
                }
            }
        }
        return res;
    }

    private static <T> void handleAnnotations(
        final Class<T> clazz,
        final Converter<T> converter) {
        try {
            for (final Annotation a : clazz.getAnnotations()) {
                final HandlerClass handlerClass
                    = a.annotationType().getAnnotation(
                        Convert.HandlerClass.class);
                if (handlerClass != null) {
                    handleAnnotation(clazz, converter, a, handlerClass);
                }
            }
        } catch (final InstantiationException e) {
            throw new ConvertReflectionException(clazz, e);
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(clazz, e);
        }
    }

    private static <T, A extends Annotation> void handleAnnotation(
        final Class<T> clazz,
        final Converter<T> converter,
        final A a,
        final HandlerClass handlerClass)
        throws InstantiationException, IllegalAccessException {
        @SuppressWarnings("unchecked")
        final AnnotationHandler<A> handler =
            (AnnotationHandler<A>) handlerClass.value().newInstance();
        handler.handle(clazz, converter, a);
    }

    private <T> Converter<T> generateConverter(final Class<T> clazz) {
        if (clazz.isEnum()) {
            return generateEnumConverter(clazz);
        }
        try {
            for (final Annotation a : clazz.getAnnotations()) {
                final ConverterFactoryClass factoryClass
                    = a.annotationType().getAnnotation(
                        Convert.ConverterFactoryClass.class);
                if (factoryClass != null) {
                    return getMethod(clazz, a, factoryClass);
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

    // I happen to know that clazz is an enum here, but try telling the
    // type system that...
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private static <T> Converter<T> generateEnumConverter(final Class<T> clazz) {
        return new EnumConverter(clazz);
    }

    private <T, A extends Annotation> Converter<T> getMethod(
        final Class<T> clazz,
        final A a,
        final ConverterFactoryClass factoryClass)
                        throws InstantiationException, IllegalAccessException {
        final Converter<T> res = getFactoryInstance(factoryClass.value())
                        .converter(clazz, a);
        if (!res.getResultClass().equals(clazz)) {
            throw new ConvertReflectionException(clazz,
                            "Didn't get appropriate converter!");
        }
        return res;
    }

    @SuppressWarnings("unchecked")
    private <A extends Annotation> ConverterFactory<A> getFactoryInstance(
        final Class<? extends ConverterFactory<?>> clazz)
                        throws InstantiationException, IllegalAccessException {
        ConverterFactory<?> res = factoryCache.get(clazz);
        if (res == null) {
            res = clazz.newInstance();
            factoryCache.put(clazz, res);
        }
        return (ConverterFactory<A>) res;
    }
}
