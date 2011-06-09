package net.lshift.spki.convert;

import java.lang.annotation.Annotation;
import java.util.List;

import net.lshift.spki.convert.Convert.SequenceConverted;

public class SequenceConverterFactory
    implements ConverterFactory {

    @Override
    public <T> Converter<T> converter(final Class<T> clazz, final Annotation a) {
        final SequenceConverted aa = (Convert.SequenceConverted) a;
        List<FieldConvertInfo> m = NameBeanConverterFactory.getFieldMap(clazz);
        if (m.size() != 1) {
            throw new ConvertReflectionException(clazz,
                "Class must have one field");
        }
        return new SequenceConverter<T>(clazz, aa.value(), m.get(0).field);
    }

}
