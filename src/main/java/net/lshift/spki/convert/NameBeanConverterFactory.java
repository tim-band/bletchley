package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public class NameBeanConverterFactory
implements ConverterFactory<Convert.ByName>
{
    public <T> Converter<T> converter(final Class<T> clazz, final Convert.ByName a) {
        final List<FieldConvertInfo> fields = getFieldMap(clazz);
        return new NameBeanConverter<T>(clazz, a.value(), fields);
    }

    private <T> List<FieldConvertInfo> getFieldMap(final Class<T> clazz) {
        final List<FieldConvertInfo> fields = new ArrayList<FieldConvertInfo>();
        addFields(clazz, fields);
        return fields;
    }

    private <T> void addFields(final Class<T> clazz, final List<FieldConvertInfo> fields) {
        final Class<? super T> sup = clazz.getSuperclass();
        if (sup != null) {
            addFields(sup, fields);
        }
        for (final Field f: clazz.getDeclaredFields()) {
            fields.add(new FieldConvertInfo(f));
        }
    }
}
