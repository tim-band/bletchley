package net.lshift.spki.convert;

import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.convert.Convert.ConverterFactoryClass;
import net.lshift.spki.convert.Convert.HandlerClass;

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

    private synchronized <T> void registerInternal(final Converter<T> converter) {
        Class<T> clazz = converter.getResultClass();
        final Converter<?> already = converterMap.get(clazz);
        if (already == null) {
            converterMap.put(clazz, converter);
        }
    }

    /**
     * Register this converter, unless we already have a converter for this
     * result class.
     */
    public static <T> void register(final Converter<T> converter) {
        REGISTRY.registerInternal(converter);
    }

    static {
        resetRegistry();
    }

    public static void resetRegistry() {
        REGISTRY.resetRegistryInternal();
    }

    private synchronized void resetRegistryInternal() {
        converterMap.clear();
        registerInternal(new SexpConverter());
        registerInternal(new ByteArrayConverter());
        registerInternal(new StringConverter());
        registerInternal(new BigIntegerConverter());
        registerInternal(new DateConverter());
        registerInternal(new URIConverter());
        registerInternal(new URLConverter());
        registerInternal(new UUIDConverter());
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
            handleAnnotations(clazz);
        }
        return res;
    }

    private <T> void handleAnnotations(final Class<T> clazz) {
        try {
            for (final Annotation a : clazz.getAnnotations()) {
                final HandlerClass handlerClass
                    = a.annotationType().getAnnotation(
                        Convert.HandlerClass.class);
                if (handlerClass != null) {
                    handleAnnotation(clazz, a, handlerClass);
                }
            }
        } catch (InstantiationException e) {
            throw new ConvertReflectionException(clazz, e);
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(clazz, e);
        }
    }

    private <T, A extends Annotation> void handleAnnotation(
        final Class<T> clazz,
        final A a,
        final HandlerClass handlerClass)
        throws InstantiationException, IllegalAccessException {
        @SuppressWarnings("unchecked")
        AnnotationHandler<A> handler =
            (AnnotationHandler<A>) handlerClass.value().newInstance();
        handler.handle(clazz, a);
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
    private <T> Converter<T> generateEnumConverter(final Class<T> clazz) {
        return new EnumConverter(clazz);
    }

    private <T, A extends Annotation> Converter<T> getMethod(
        final Class<T> clazz,
        final A a,
        final ConverterFactoryClass factoryClass)
        throws InstantiationException, IllegalAccessException {
        // FIXME: cache these?
        @SuppressWarnings("unchecked")
        final ConverterFactory<A> factoryInstance
            = (ConverterFactory<A>) factoryClass.value().newInstance();
        final Converter<T> res = factoryInstance.converter(clazz, a);
        if (!res.getResultClass().equals(clazz)) {
            throw new ConvertReflectionException(clazz,
                "Didn't get appropriate converter!");
        }
        return res;
    }
}
