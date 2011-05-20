package net.lshift.spki.convert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import net.lshift.spki.Atom;
import net.lshift.spki.CanonicalSpkiOutputStream;
import net.lshift.spki.Constants;
import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;
import net.lshift.spki.Sexp;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

/**
 * Static utilities for conversion between SExps and objects.
 */
public class ConvertUtils
{
    public static byte[] toBytes(Sexp sexp) {
        return ((Atom)sexp).getBytes();
    }

    public static String toString(Sexp sexp)
    {
        return new String(ConvertUtils.toBytes(sexp), Constants.UTF8);
    }

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

    public static ConvertExample fromBytes(
        Class<ConvertExample> clazz,
        byte[] bytes) throws ParseException
    {
        return Convert.fromSExp(clazz, Marshal.unmarshal(bytes));
    }
}
