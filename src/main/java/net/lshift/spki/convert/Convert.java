package net.lshift.spki.convert;


import net.lshift.spki.SExp;

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
    public static <T> SExp toSExp(Class<T> clazz, T o)
    {
        return (getConverter(clazz)).toSexp(o);
    }

    @SuppressWarnings("unchecked")
    public static SExp toSExpUnchecked(Class<?> clazz, Object o)
    {
        if (!clazz.isAssignableFrom(o.getClass())) {
            throw new ConvertException("Object of unexpected type");
        }
        return ((Converter<Object>)getConverter(clazz)).toSexp(o);
    }

    public static <T> T fromSExp(Class<T> clazz, SExp sexp)
    {
        return getConverter(clazz).fromSexp(sexp);
    }
}
