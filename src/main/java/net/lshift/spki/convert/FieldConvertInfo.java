package net.lshift.spki.convert;

import java.lang.reflect.InvocationTargetException;

import org.apache.commons.beanutils.PropertyUtils;

import net.lshift.spki.SExp;

public abstract class FieldConvertInfo
{
    protected final String name;
    protected final Class<?> type;

    public FieldConvertInfo(String name, Class<?> type)
    {
        super();
        this.name = name;
        this.type = type;
    }

    public String getName()
    {
        return name;
    }

    public Class<?> getType()
    {
        return type;
    }

    public SExp genSexp(Object bean)
        throws IllegalAccessException,
            InvocationTargetException,
            NoSuchMethodException
    {
        return genSexpFromSexp(Convert.toSExp(
            PropertyUtils.getProperty(bean, name)));
    }

    public abstract SExp genSexpFromSexp(SExp sexp)
    throws IllegalAccessException,
        InvocationTargetException,
        NoSuchMethodException;

    public abstract SExp getValueSExp(SExp sexp);

    public Object getValue(SExp sexp) {
        return Convert.fromSExp(type, getValueSExp(sexp));
    }
}
