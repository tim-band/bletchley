package net.lshift.spki.convert;

/**
 * Superclass for a class that's converted by being "packed" into a simpler
 * class.
 */
public abstract class PackConvertible
    implements Convertible {
    public abstract Object pack();

    // public abstract static this.class unpack(Object);

    public static <T extends PackConvertible> Converter<T> getConverter(
        Class<T> clazz) {
        return new PackConverter<T>(clazz);
    }
}
