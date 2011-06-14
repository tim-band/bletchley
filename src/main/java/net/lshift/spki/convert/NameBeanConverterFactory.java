package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public class NameBeanConverterFactory
implements ConverterFactory<Convert.ByName>
{
    public <T> Converter<T> converter(Class<T> clazz, Convert.ByName a) {
        List<FieldConvertInfo> fields = getFieldMap(clazz);
        return new NameBeanConverter<T>(clazz, a.value(), fields);
    }

    private <T> List<FieldConvertInfo> getFieldMap(Class<T> clazz) {
        List<FieldConvertInfo> fields = new ArrayList<FieldConvertInfo>();
        addFields(clazz, fields);
        return fields;
    }

    private <T> void addFields(Class<T> clazz, List<FieldConvertInfo> fields) {
        Class<? super T> sup = clazz.getSuperclass();
        if (sup != null) {
            addFields(sup, fields);
        }
        for (Field f: clazz.getDeclaredFields()) {
            fields.add(new FieldConvertInfo(f));
        }
    }
}
