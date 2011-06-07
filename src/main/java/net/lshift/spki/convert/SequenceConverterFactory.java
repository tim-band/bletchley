package net.lshift.spki.convert;

public class SequenceConverterFactory
    implements ConverterFactory {

    @Override
    public <T> Converter<T> converter(Class<T> c) {
        return new SequenceConverter<T>(c);
    }

}
