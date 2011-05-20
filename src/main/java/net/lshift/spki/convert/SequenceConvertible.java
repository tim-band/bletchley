package net.lshift.spki.convert;

/**
 * Superclass for a class that's converted as a sequence
 */
public class SequenceConvertible implements Convertible
{
    public static <T extends SequenceConvertible> Converter<T> getConverter(
        Class<T> clazz)
    {
        return new SequenceConverter<T>(clazz);
    }
}
