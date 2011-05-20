package net.lshift.spki.convert;

/**
 * Superclass for objects that should be converted using the PositionBean
 * protocol
 */
public class PositionBeanConvertible implements Convertible
{
    public static <T> Converter<T> getConverter(Class<T> clazz) {
        return new PositionBeanConverter<T>(clazz);
    }
}
