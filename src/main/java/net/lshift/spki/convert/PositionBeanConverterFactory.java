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
            try {
                fields.add(new FieldConvertInfo(
                    getField(clazz, fname)));
            } catch (final SecurityException e) {
                throw new ConvertReflectionException(e);
            } catch (final NoSuchFieldException e) {
                throw new ConvertReflectionException(e);
            }
        }
        return new PositionBeanConverter<T>(clazz, aa.name(), fields);
    }

    private <T> Field getField(final Class<T> clazz, final String fname)
        throws NoSuchFieldException {
        try {
            return clazz.getDeclaredField(fname);
        } catch (final NoSuchFieldException e) {
            final Class<? super T> sup = clazz.getSuperclass();
            if (sup == null) {
                throw e;
            }
            return getField(sup, fname);
        }
    }
}
