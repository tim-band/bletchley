package net.lshift.spki.convert;

import java.util.List;

public class SequenceConverterFactory
    implements ConverterFactory<Convert.SequenceConverted> {

    @Override
    public <T> Converter<T> converter(final Class<T> clazz, final Convert.SequenceConverted a) {
        List<FieldConvertInfo> m = NameBeanConverterFactory.getFieldMap(clazz);
        if (m.size() != 1) {
            throw new ConvertReflectionException(clazz,
                "Class must have one field");
        }
        return new SequenceConverter<T>(clazz, a.value(), m.get(0).field);
    }
}
