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
}
