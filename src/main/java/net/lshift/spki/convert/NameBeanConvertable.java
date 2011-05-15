package net.lshift.spki.convert;

public class NameBeanConvertable implements Convertable
{
    public static <T> Converter<T> getConverter(Class<T> clazz) {
        return new NameBeanConverter<T>(clazz);
    }
}
