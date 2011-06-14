package net.lshift.spki.convert;

public class PositionBeanConverterFactory
implements ConverterFactory
{
    public <T> Converter<T> converter(Class<T> clazz) {
        return new PositionBeanConverter<T>(clazz);
    }
}
