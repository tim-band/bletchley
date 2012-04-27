package net.lshift.spki.convert;

import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

public class Converting {
    private static final Map<String, Class<?>> discrimMap
        = new HashMap<String,Class<?>>();

    @SuppressWarnings("unchecked")
    public <T> T read(
        final Class<T> clazz,
        final Map<Class<?>, Converter<?>> extraConverters,
        final Sexp sexp)
        throws InvalidInputException {
        // FIXME: this sure is ugly!
        if (clazz == Sexp.class) {
            return (T) sexp;
        }
        final T res = getConverter(extraConverters, clazz).read(this, sexp);
        // FIXME: so is this!
        // FIXME: use the dynamic class here?
        if (res instanceof SexpBacked) {
            ((SexpBacked)res).setSexp(sexp);
        }
        return res;
    }

    @SuppressWarnings("unchecked")
    public static <T> Converter<T> getConverter(
        final Map<Class<?>, Converter<?>> extraConverters,
        final Class<T> clazz) {
        if (extraConverters != null && extraConverters.containsKey(clazz)) {
            return (Converter<T>) extraConverters.get(clazz);
        } else {
            return Registry.getConverter(clazz);
        }
    }

    public <T> T read(
        final Class<T> clazz,
        final Sexp sexp)
        throws InvalidInputException {
        return read(clazz, null, sexp);
    }

    private <U> String discrimMapKey(final Class<U> clazz, final String name) {
        return clazz.getCanonicalName() + ";" + name;
    }

    @SuppressWarnings("unchecked")
    public synchronized <U> Class<? extends U> getExtraDiscrim(
        final Class<U> clazz,
        final String name) {
        // FIXME: class <-> canonicalName is not a 1-1 map.
        return (Class<? extends U>)
            discrimMap.get(discrimMapKey(clazz, name));
    }

    public synchronized void register(final Class<?> clazz) {
        Class<?> superclass = getDiscriminatedSuperclass(clazz, clazz);
        if (superclass == null) {
            throw new ConvertReflectionException(clazz,
                "has no discriminated superclass");
        }
        final Converter<?> converter = Registry.getConverter(clazz);
        if (!(converter instanceof ListConverter<?>)) {
            throw new ConvertReflectionException(clazz,
                "defines no name, cannot be instance of a discrim");
        }
        final String key = discrimMapKey(
            superclass, ((ListConverter<?>)converter).getName());
        if (discrimMap.containsKey(key)) {
            if (discrimMap.get(key) == clazz)
                return;
            throw new ConvertReflectionException(clazz,
                "cannot claim this key, " + discrimMap.get(key).getSimpleName() +
                " has it: " + key);
        }
        discrimMap.put(key, clazz);
    }

    private Class<?> getDiscriminatedSuperclass(Class<?> clazz, Class<?> sup) {
        if (sup == null)
            return null;
        if (sup.getAnnotation(Convert.Discriminated.class) != null)
            return sup;
        Class<?> res = getDiscriminatedSuperclass(clazz, sup.getSuperclass());
        if (res != null)
            return res;
        for (Class<?> supsup: sup.getInterfaces()) {
            res = getDiscriminatedSuperclass(clazz, supsup);
            if (res != null)
                return res;
        }
        return null;
    }
}
