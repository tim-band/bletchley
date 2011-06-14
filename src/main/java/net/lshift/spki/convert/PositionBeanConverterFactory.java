package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public class PositionBeanConverterFactory
implements ConverterFactory<Convert.ByPosition>
{
    public <T> Converter<T> converter(Class<T> clazz, Convert.ByPosition a) {
        List<FieldConvertInfo> fields = new ArrayList<FieldConvertInfo>();
        for (String fname: a.fields()) {
            try {
                fields.add(new FieldConvertInfo(
                    getField(clazz, fname)));
            } catch (SecurityException e) {
                throw new ConvertReflectionException(e);
            } catch (NoSuchFieldException e) {
                throw new ConvertReflectionException(e);
            }
        }
        return new PositionBeanConverter<T>(clazz, a.name(), fields);
    }

    private <T> Field getField(Class<T> clazz, String fname)
        throws NoSuchFieldException {
        try {
            return clazz.getDeclaredField(fname);
        } catch (NoSuchFieldException e) {
            Class<? super T> sup = clazz.getSuperclass();
            if (sup == null) {
                throw e;
            }
            return getField(sup, fname);
        }
    }
}
