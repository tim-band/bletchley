package net.lshift.spki.convert;

import java.lang.annotation.Annotation;

import net.lshift.spki.convert.Convert.SequenceConverted;

public class SequenceConverterFactory
    implements ConverterFactory {

    @Override
    public <T> Converter<T> converter(final Class<T> c, final Annotation a) {
        final SequenceConverted aa = (Convert.SequenceConverted) a;
        return new SequenceConverter<T>(c, aa.value());
    }

}
