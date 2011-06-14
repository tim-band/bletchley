package net.lshift.spki.convert;

public class NameBeanConverterFactory
implements ConverterFactory
{
    public <T> Converter<T> converter(Class<T> clazz) {
        return new NameBeanConverter<T>(clazz);
    }
}
