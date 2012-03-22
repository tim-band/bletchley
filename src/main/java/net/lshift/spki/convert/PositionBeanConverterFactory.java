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
        final List<FieldConvertInfo> fields = new ArrayList<FieldConvertInfo>();
        for (final String fname: a.fields()) {
            fields.add(new FieldConvertInfo(
                getField(clazz, clazz, fname)));
        }
        return new PositionBeanConverter<T>(clazz, a.name(), fields);
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
