package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.Map.Entry;

import sun.misc.Unsafe;

public class DeserializingConstructor {
    private static final Unsafe unsafe;
    static {
        Field field;
        try {
            field = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            unsafe = (sun.misc.Unsafe) field.get(null);
        } catch (final SecurityException e) {
            throw new RuntimeException(e);
        } catch (final NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (final IllegalArgumentException e) {
            // TODO Auto-generated catch block
            throw new RuntimeException(e);
        } catch (final IllegalAccessException e) {
            // TODO Auto-generated catch block
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
