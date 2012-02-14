package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.PositionSequence;

public class PositionSequenceConverterFactory
    implements ConverterFactory<Convert.PositionSequence> {

    @Override
    public <T> Converter<T> converter(Class<T> clazz, PositionSequence a) {
        return new PositionSequenceConverter<T>(
            clazz, a.name(),
            PositionBeanConverterFactory.getFields(clazz, a.fields()),
            PositionBeanConverterFactory.getField(clazz, a.seq()));
    }
}
