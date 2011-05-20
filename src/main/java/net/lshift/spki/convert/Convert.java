package net.lshift.spki.convert;


import net.lshift.spki.Sexp;

/**
 * Static utilities for converting between classes and SExps based on
 * a registry of converters for classes.
 */
public class Convert
{
    public static final Registry REGISTRY = new Registry();

    private static <T> Converter<T> getConverter(Class<T> clazz)
    {
        return REGISTRY.getConverter(clazz);
    }

    public static <T> T fromSExp(Class<T> clazz, Sexp sexp)
    {
        return getConverter(clazz).fromSexp(sexp);
    }
}
