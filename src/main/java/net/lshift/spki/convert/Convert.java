package net.lshift.spki.convert;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import net.lshift.spki.CanonicalSpkiInputStream;
import net.lshift.spki.ParseException;

/**
 * Static utilities for converting between classes and SExps based on
 * a registry of converters for classes.
 * FIXME: work out division of labour between this and ConvertUtils.
 */
public class Convert
{
    public static final Registry REGISTRY = new Registry();

    public static <T> T read(Class<T> clazz, InputStream is)
        throws ParseException,
            IOException
    {
        try {
            ConvertInputStream in
                = new ConvertInputStream(new CanonicalSpkiInputStream(is));
            return in.read(clazz);
        } finally {
            is.close();
        }
    }

    public static <T> T fromBytes(
        Class<T> clazz,
        byte [] bytes) throws ParseException
    {
        try {
            return read(clazz, new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            throw new RuntimeException("CANTHAPPEN", e);
        }
    }
}
