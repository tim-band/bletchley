package net.lshift.spki.convert;

/**
 * Superclass for a class that's converted as a sequence
 */
public class SequenceConvertable implements Convertable
{
    public static <T extends SequenceConvertable> Converter<T> getConverter(
        Class<T> clazz)
    {
        return new SequenceConverter<T>(clazz);
    }
}
