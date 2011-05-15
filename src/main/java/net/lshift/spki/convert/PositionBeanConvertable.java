package net.lshift.spki.convert;

public class PositionBeanConvertable implements Convertable
{
    public static <T> Converter<T> getConverter(Class<T> clazz) {
        return new PositionBeanConverter<T>(clazz);
    }
}
