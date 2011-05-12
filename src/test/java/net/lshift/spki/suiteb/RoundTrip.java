package net.lshift.spki.suiteb;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SExp;
import net.lshift.spki.convert.Convert;

public class RoundTrip
{
    private static final Logger LOG = LoggerFactory.getLogger(RoundTrip.class);
    @SuppressWarnings("unchecked")
    public static <T> T packableRoundTrip(T o)
    {
        try {
            Class<?> outClass = o.getClass();
            Object packed = outClass.getMethod("pack").invoke(o);
            Object unpacked = convertableRoundTrip(packed);
            Method unpack = outClass.getMethod("unpack", packed.getClass());
            return (T) unpack.invoke(null, unpacked);
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T convertableRoundTrip(T o)
    {
        try {
            SExp sexp = Convert.toSExp(o);
            LOG.info(PrettyPrinter.prettyPrint(sexp));
            byte[] bytes = Marshal.marshal(sexp);
            return (T) Convert.fromBytes(o.getClass(), bytes);
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }
}
