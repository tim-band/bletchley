package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * Use a PositionBeanConverter for this class.
 */
public class PositionBeanConverterFactory
implements ConverterFactory<Convert.ByPosition>
{
    @Override
    public <T> Converter<T> converter(final Class<T> clazz, final Convert.ByPosition a) {
        return new PositionBeanConverter<T>(
            clazz, a.name(), getFields(clazz, a.fields()));
    }

    public static <T> List<FieldConvertInfo> getFields(
        final Class<T> clazz,
        final String[] fieldNames) {
        final List<FieldConvertInfo> fields = new ArrayList<FieldConvertInfo>();
        for (final String fname: fieldNames) {
            fields.add(new FieldConvertInfo(clazz, getField(clazz, fname)));
        }
        return fields;
    }

    public static <T> Field getField(final Class<T> clazz, final String fname) {
        return getField(clazz, clazz, fname);
    }

    private static <T> Field getField(
        final Class<T> clazz,
        final Class<? super T> c,
        final String fname) {
        try {
            return c.getDeclaredField(fname);
        } catch (final NoSuchFieldException e) {
            final Class<? super T> sup = c.getSuperclass();
            if (sup == null) {
                throw new ConvertReflectionException(clazz, e);
            }
            return getField(clazz, sup, fname);
        }
    }
}
