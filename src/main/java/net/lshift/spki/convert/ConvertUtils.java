package net.lshift.spki.convert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import net.lshift.spki.CanonicalSpkiInputStream;
import net.lshift.spki.CanonicalSpkiOutputStream;
import net.lshift.spki.ParseException;

/**
 * Static utilities for conversion between SExps and objects.
 * FIXME: work out division of labour between this and Convert
 */
public class ConvertUtils
{
    public static <T> void initialize(Class<T> clazz)
        throws AssertionError
    {
        // Ensure the class is initialized
        // in case it statically registers converters
        // http://java.sun.com/j2se/1.5.0/compatibility.html
        try {
            Class.forName(clazz.getName(), true, clazz.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new AssertionError(e);  // Can't happen
        }
    }

    public static <T> byte[] toBytes(Class<T> clazz, T o)
    {
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            ConvertOutputStream out
                = new ConvertOutputStream(new CanonicalSpkiOutputStream(os));
            out.write(clazz, o);
            out.close();
            return os.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(
                "ByteArrayOutputStream cannot throw IOException", e);
        }
    }

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
