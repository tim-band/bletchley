package net.lshift.spki.convert;

public abstract class PackConvertable
    implements Convertable
{
    public abstract Object pack();

    public static <T extends PackConvertable> Converter<T> getConverter(
        Class<T> clazz)
    {
        return new PackConverter<T>(clazz);
    }
}
