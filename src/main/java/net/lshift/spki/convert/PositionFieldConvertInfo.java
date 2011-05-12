package net.lshift.spki.convert;

import java.lang.reflect.InvocationTargetException;

import net.lshift.spki.SExp;
import net.lshift.spki.SList;

import org.apache.commons.beanutils.PropertyUtils;

public class PositionFieldConvertInfo
    extends FieldConvertInfo
{
    private final int position;

    public PositionFieldConvertInfo(String name, Class<?> type, int position)
    {
        super(name, type);
        this.position = position;
    }

    public SExp genSexp(Object bean)
        throws IllegalAccessException,
            InvocationTargetException,
            NoSuchMethodException
    {
        return Convert.toSExp(PropertyUtils.getProperty(bean, name));
    }

    public Object getValue(SExp sexp) {
        return Convert.fromSExp(type, ((SList)sexp).getSparts()[position -1]);
    }
}
