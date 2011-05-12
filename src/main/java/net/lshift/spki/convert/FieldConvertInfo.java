package net.lshift.spki.convert;

import java.lang.reflect.InvocationTargetException;

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

    public abstract SExp genSexp(Object bean)
        throws IllegalAccessException,
            InvocationTargetException,
            NoSuchMethodException;

    public abstract Object getValue(SExp sexp);
}
