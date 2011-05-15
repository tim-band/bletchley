package net.lshift.spki.convert;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;
import net.lshift.spki.SExp;

public class Convert
{
    private static final Registry REGISTRY = new Registry();

    private static <T> Converter<T> getConverter(Class<T> clazz)
    {
        return REGISTRY.getConverter(clazz);
    }

    @SuppressWarnings("unchecked")
    public static SExp toSExp(Object o)
    {
        return ((Converter<Object>) getConverter(o.getClass())).toSexp(o);
    }

    public static <T> T fromSExp(Class<T> clazz, SExp sexp)
    {
        return getConverter(clazz).fromSexp(sexp);
    }

    public static void write(Openable open, Object o) throws IOException
    {
        final OutputStream os = open.write();
        try {
            Marshal.marshal(os, toSExp(o));
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
