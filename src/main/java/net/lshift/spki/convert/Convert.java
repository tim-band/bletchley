package net.lshift.spki.convert;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;
import net.lshift.spki.SExp;

public class Convert
{
    public static final Registry REGISTRY = new Registry();

    private static <T> Converter<T> getConverter(Class<T> clazz)
    {
        return REGISTRY.getConverter(clazz);
    }

    //public static <T> SExp toSExp(Class<T> clazz, T o)
    @SuppressWarnings("unchecked")
    public static SExp toSExp(Class<?> clazz, Object o)
    {
        return ((Converter<Object>)getConverter(clazz)).toSexp(o);
    }

    public static <T> T fromSExp(Class<T> clazz, SExp sexp)
    {
        return getConverter(clazz).fromSexp(sexp);
    }

    public static <T> void write(Openable open, Class<T> clazz, T o)
        throws IOException
    {
        final OutputStream os = open.write();
        try {
            Marshal.marshal(os, toSExp(clazz, o));
        } finally {
            os.close();
        }
    }

    public static <T> T read(Class<T> clazz, Openable open) throws ParseException, IOException
    {
        final InputStream is = open.read();
        try {
            return fromSExp(clazz, Marshal.unmarshal(is));
        } finally {
            is.close();
        }
    }
}
