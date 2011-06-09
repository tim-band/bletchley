package net.lshift.spki.convert;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.convert.Convert.ByPosition;

public class PositionBeanConverterFactory
implements ConverterFactory
{
    public <T> Converter<T> converter(final Class<T> clazz, final Annotation a) {
        final ByPosition aa = (Convert.ByPosition) a;
        final List<FieldConvertInfo> fields = new ArrayList<FieldConvertInfo>();
        for (final String fname: aa.fields()) {
            fields.add(new FieldConvertInfo(
                getField(clazz, clazz, fname)));
        }
        return new PositionBeanConverter<T>(clazz, aa.name(), fields);
    }

    private <T> Field getField(
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
