package net.lshift.spki.convert;

import net.lshift.spki.Atom;
import net.lshift.spki.Constants;
import net.lshift.spki.SExp;

/**
 * Static utilities for conversion between SExps and objects.
 */
public class ConvertUtils
{
    public static byte[] toBytes(SExp sexp) {
        return ((Atom)sexp).getBytes();
    }

    public static String toString(SExp sexp)
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
}
