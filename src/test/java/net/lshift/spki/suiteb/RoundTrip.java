package net.lshift.spki.suiteb;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SExp;
import net.lshift.spki.convert.Convert;

public class RoundTrip
{
    @SuppressWarnings("unchecked")
    public static <T> T roundTrip(T o)
    {
        try {
            Class<?> outClass = o.getClass();
            Object packed = outClass.getMethod("pack").invoke(o);
            SExp sexp = Convert.toSExp(packed);
            PrettyPrinter.prettyPrint(System.out, sexp);
            byte[] bytes = Marshal.marshal(sexp);
            Object unpacked = Convert.fromBytes(packed.getClass(), bytes);
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
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }
}
