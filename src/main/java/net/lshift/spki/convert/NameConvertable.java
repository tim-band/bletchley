package net.lshift.spki.convert;

import static net.lshift.spki.Create.list;

import java.lang.reflect.InvocationTargetException;

import net.lshift.spki.Atom;
import net.lshift.spki.Create;
import net.lshift.spki.SExp;
import net.lshift.spki.SList;

import org.apache.commons.beanutils.PropertyUtils;

public class NameConvertable
    extends Convertable
{
    public NameConvertable(String name, Class<?> type)
    {
        super(name, type);
    }

    @Override
    public SExp genSexp(Object bean)
        throws IllegalAccessException,
            InvocationTargetException,
            NoSuchMethodException
    {
        return list(name, Convert.toSExp(
            PropertyUtils.getProperty(bean, name)));
    }

    @Override
    public Object getValue(SExp sexp) {
        SExp[] sexpVal = getSExp(name, sexp).getSparts();
        assert sexpVal.length == 1;
        return Convert.fromSExp(type, sexpVal[0]);
    }

    private static SList getSExp(String string, SExp sexp) {
        Atom match = Create.atom(string);
        for (SExp s: ((SList)sexp).getSparts()) {
            if (s instanceof SList) {
                SList sl = (SList) s;
                if (match.equals(sl.getHead())) {
                    return sl;
                }
            }
        }
        throw new ConvertException("No sexp with key " + string
                + " found in sexp " + ((SList)sexp).getHead().getBytes());
    }
}
