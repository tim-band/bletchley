package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.SequenceConverted;

public class SequenceConverterFactory
    implements ConverterFactory<Convert.SequenceConverted> {

    @Override
    public <T> Converter<T> converter(Class<T> c, Convert.SequenceConverted a) {
        SequenceConverted aa = a;
        return new SequenceConverter<T>(c, aa.value());
    }
}
