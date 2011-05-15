package net.lshift.spki.convert;


import net.lshift.spki.Marshal;
import net.lshift.spki.SExp;

public class Convert
{
    private static final Registry REGISTRY = new Registry();

    @SuppressWarnings("unchecked")
    public static SExp toSExp(Object o)
    {
        return ((Converter<Object>) getConverter(o.getClass())).toSexp(o);
    }

    private static <T> Converter<T> getConverter(Class<T> clazz)
    {
        return REGISTRY.getConverter(clazz);
    }

    public static byte[] toBytes(Object o) {
        return Marshal.marshal(toSExp(o));
    }

    public static <T> T fromSExp(Class<T> class1, SExp sexp)
    {
        return getConverter(class1).fromSexp(sexp);
    }

    public static <T> T fromBytes(Class<T> class1, byte[] bytes)
        throws net.lshift.spki.ParseException
    {
        return fromSExp(class1, Marshal.unmarshal(bytes));
    }
}
