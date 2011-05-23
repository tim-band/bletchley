package net.lshift.spki.convert;

/**
 * Classes with this interface must have a static method that returns a
 * suitable converter for that class; it's then looked up via reflection.
 */
public interface Convertible {
    // public static Converter<T> getConverter(Class<T> clazz);
}
