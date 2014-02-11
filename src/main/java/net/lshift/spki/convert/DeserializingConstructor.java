package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.Map.Entry;

import sun.misc.Unsafe;

/**
 * Build an object the way a deserializer would: use
 * unsafe.allocateInstance to sidestep the constructor and force the
 * fields to the values in the map.
 */
@SuppressWarnings("restriction")
public class DeserializingConstructor {
    private static final Unsafe unsafe = getUnsafe();

    private static Unsafe getUnsafe() {
        try {
            Field field = Unsafe.class.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            return (Unsafe) field.get(null);
        } catch (final NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (final IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T make(final Class<T> clazz, final Map<Field, Object> fields)
        throws InstantiationException,
            SecurityException,
            IllegalArgumentException,
            IllegalAccessException {
        final T res = (T) unsafe.allocateInstance(clazz);
        for (final Entry<Field, Object> f: fields.entrySet()) {
            final Field field = f.getKey();
            field.setAccessible(true);
            field.set(res, f.getValue());
        }
        return res;
    }

    public static <T> T convertMake(final Class<T> clazz, final Map<Field, Object> fields) {
        try {
            return DeserializingConstructor.make(clazz, fields);
        } catch (final InstantiationException e) {
            throw new ConvertReflectionException(clazz, e);
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(clazz, e);
        }
    }
}
