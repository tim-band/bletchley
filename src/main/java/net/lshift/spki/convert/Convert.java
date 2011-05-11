package net.lshift.spki.convert;

import static net.lshift.spki.Create.atom;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import net.lshift.spki.Atom;
import net.lshift.spki.Constants;
import net.lshift.spki.SExp;

public class Convert
{
    private static String sb(SExp b) {
        return new String(((Atom)b).getBytes(), Constants.UTF8);
    }

    public static SExp toSExp(Object o)
    {
        if (o instanceof byte[]) {
            return atom((byte[])o);
        } else if (o instanceof String) {
            return atom((String)o);
        } else if (o instanceof BigInteger) {
            return atom((BigInteger)o);
        } else if (o instanceof Date) {
            return atom((Date)o);
        }
        // FIXME: cache these, use them for byte etc
        ConvertInfo<?> convertInfo = ConvertInfo.getConversion(o.getClass());
        try {
            return convertInfo.toSExpCast(o);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T fromSExp(Class<T> class1, SExp sexp)
    {
        try {
            if (class1.equals(byte[].class)) {
                return (T) ((Atom)sexp).getBytes();
            } else if (class1.equals(String.class)) {
                return (T) sb(sexp);
            } else if (class1.equals(BigInteger.class)) {
                return (T) new BigInteger(((Atom)sexp).getBytes());
            } else if (class1.equals(Date.class)) {
                    return (T) Constants.DATE_FORMAT.parse(sb(sexp));
            }
            ConvertInfo<?> convertInfo = ConvertInfo.getConversion(class1);
            return (T) convertInfo.fromSExp(sexp);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }
}
