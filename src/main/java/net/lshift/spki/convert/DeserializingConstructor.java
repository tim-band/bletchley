package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.Map.Entry;

import sun.misc.Unsafe;

/**
 * Build an object the way a desrializer would: use
 * unsafe.allocateInstance to sidestep the constructor and force the
 * fields to the values in the map.
 */
@SuppressWarnings("restriction")
public class DeserializingConstructor {
    private static final Unsafe unsafe;
    static {
        Field field;
        try {
            field = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            unsafe = (sun.misc.Unsafe) field.get(null);
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

}
