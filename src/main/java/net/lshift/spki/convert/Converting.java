package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert.InstanceOf;
import net.lshift.spki.sexpform.Sexp;

public class Converting {
    private static final Field SEXP_FIELD = getSexpField();
    private static final Map<String, Class<?>> discrimMap
        = new HashMap<String,Class<?>>();

    private static Field getSexpField() {
        try {
            final Field res = SexpBacked.class.getDeclaredField("sexp");
            res.setAccessible(true);
            return res;
        } catch (final NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

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
        if (SexpBacked.class.isAssignableFrom(clazz)) {
            try {
                SEXP_FIELD.set(res, sexp);
            } catch (final IllegalAccessException e) {
                throw new RuntimeException(e);
            }
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

    private <U> String discrimMapKey(Class<U> clazz, String name) {
        return clazz.getCanonicalName() + ";" + name;
    }

    @SuppressWarnings("unchecked")
    public synchronized <U> Class<? extends U> getExtraDiscrim(Class<U> clazz, String name) {
        // FIXME: class <-> canonicalName is not a 1-1 map.
        return (Class<? extends U>)
            discrimMap.get(discrimMapKey(clazz, name));
    }

    public synchronized void register(Class<?> clazz) {
        InstanceOf instanceOf = clazz.getAnnotation(Convert.InstanceOf.class);
        if (instanceOf == null)
            throw new ConvertReflectionException(clazz, "has no InstanceOf annotation");
        if (!instanceOf.value().isAssignableFrom(clazz)) {
            throw new ConvertReflectionException(clazz,
                " is not a subclass of: " + instanceOf.value().getSimpleName());
        }
        Converter<?> converter = Registry.getConverter(clazz);
        if (!(converter instanceof ListConverter<?>)) {
            throw new ConvertReflectionException(clazz,
                "defines no name, cannot be instance of a discrim");
        }
        final String key = discrimMapKey(
            instanceOf.value(), ((ListConverter<?>)converter).getName());
        if (discrimMap.containsKey(key)) {
            if (discrimMap.get(key) == clazz)
                return;
            throw new ConvertReflectionException(clazz,
                "cannot claim this key, " + discrimMap.get(key).getSimpleName() +
                " has it: " + key);
        }
        discrimMap.put(key, clazz);
    }
}
