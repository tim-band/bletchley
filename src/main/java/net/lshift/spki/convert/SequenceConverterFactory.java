package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.SequenceConverted;

public class SequenceConverterFactory
    implements ConverterFactory<Convert.SequenceConverted> {

    @Override
    public <T> Converter<T> converter(final Class<T> c, final Convert.SequenceConverted a) {
        final SequenceConverted aa = a;
        return new SequenceConverter<T>(c, aa.value());
    }
}
