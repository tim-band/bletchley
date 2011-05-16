package net.lshift.spki.convert;

/**
 * Superclass for a class that's converted by being "packed" into a simpler
 * class.
 */
public abstract class PackConvertable
    implements Convertable
{
    public abstract Object pack();

    // public abstract static this.class unpack(Object);

    public static <T extends PackConvertable> Converter<T> getConverter(
        Class<T> clazz)
    {
        return new PackConverter<T>(clazz);
    }
}
