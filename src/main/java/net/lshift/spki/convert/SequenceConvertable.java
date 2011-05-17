package net.lshift.spki.convert;

public class SequenceConvertable implements Convertable
{
    public static <T extends SequenceConvertable> Converter<T> getConverter(
        Class<T> clazz)
    {
        return new SequenceConverter<T>(clazz);
    }
}
