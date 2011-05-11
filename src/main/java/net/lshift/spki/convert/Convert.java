package net.lshift.spki.convert;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.Create.list;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import net.lshift.spki.Atom;
import net.lshift.spki.Constants;
import net.lshift.spki.Get;
import net.lshift.spki.SExp;
import net.lshift.spki.SList;

import org.apache.commons.beanutils.PropertyUtils;

public class Convert
{
    private static String sb(SExp b) {
        return new String(((Atom)b).getBytes(), Constants.UTF8);
    }

    private static Atom bs(String s) {
        return new Atom(s.getBytes(Constants.UTF8));
    }

    @SuppressWarnings("unchecked")
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
        String sexpName = o.getClass().getAnnotation(SexpName.class).value();
        try {
            ArrayList<SExp> subvalues = new ArrayList<SExp>();
            for (Map.Entry e: (Set<Map.Entry>) PropertyUtils.describe(o).entrySet()) {
                final String key = (String)e.getKey();
                if (!"class".equals(key)) {
                    subvalues.add(list(key, toSExp(e.getValue())));
                }
            }
            return list(atom(sexpName), subvalues);
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
            String sexpName = class1.getAnnotation(SexpName.class).value();
            assert bs(sexpName).equals(((SList) sexp).getHead());
            Constructor<?>[] constructors = class1.getConstructors();
            assert constructors.length == 1;
            Constructor<T> constructor = (Constructor<T>) constructors[0];
            Class<?>[] parameters = constructor.getParameterTypes();
            Annotation[][] annotations = constructor.getParameterAnnotations();
            assert parameters.length == annotations.length;
            assert parameters.length == ((SList) sexp).getSparts().length;
            Object initargs[] = new Object[parameters.length];
            for (int i = 0; i < parameters.length; i++) {
                String name = getParamName(annotations[i]);
                SList sexpVal = Get.getSExp(name, sexp);
                assert sexpVal.getSparts().length == 1;
                initargs[i] = fromSExp(
                    parameters[i], sexpVal.getSparts()[0]);
            }
            return (T) constructor.newInstance(initargs);
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

    private static String getParamName(Annotation[] annotations)
    {
        for (Annotation a: annotations) {
            if (a instanceof S) {
                return ((S)a).value();
            }
        }
        throw new RuntimeException("No annotation found in constructor param");
    }
}
