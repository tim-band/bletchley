package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public class PositionBeanConverterFactory
implements ConverterFactory<Convert.ByPosition>
{
    public <T> Converter<T> converter(final Class<T> clazz, final Convert.ByPosition a) {
        final List<FieldConvertInfo> fields = new ArrayList<FieldConvertInfo>();
        for (final String fname: a.fields()) {
            try {
                fields.add(new FieldConvertInfo(
                    getField(clazz, fname)));
            } catch (final SecurityException e) {
                throw new ConvertReflectionException(e);
            } catch (final NoSuchFieldException e) {
                throw new ConvertReflectionException(e);
            }
        }
        return new PositionBeanConverter<T>(clazz, a.name(), fields);
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
