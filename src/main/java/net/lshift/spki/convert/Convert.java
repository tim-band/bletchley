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

    // FIXME: not clear that either this or the next method should
    // allow clazz != o.getClass() in general.
    public static <T> Sexp toSExp(Class<T> clazz, T o)
    {
        return (getConverter(clazz)).toSexp(o);
    }

    @SuppressWarnings("unchecked")
    public static Sexp toSExpUnchecked(Class<?> clazz, Object o)
    {
        if (!clazz.isAssignableFrom(o.getClass())) {
            throw new ConvertException("Object of unexpected type");
        }
        return ((Converter<Object>)getConverter(clazz)).toSexp(o);
    }

    public static <T> T fromSExp(Class<T> clazz, Sexp sexp)
    {
        return getConverter(clazz).fromSexp(sexp);
    }
}
