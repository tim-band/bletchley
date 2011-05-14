package net.lshift.spki.convert;

import java.lang.reflect.InvocationTargetException;

import net.lshift.spki.SExp;
import net.lshift.spki.SList;

public class PositionFieldConvertInfo
    extends FieldConvertInfo
{
    private final int position;

    public PositionFieldConvertInfo(String name, Class<?> type, int position)
    {
        super(name, type);
        this.position = position;
    }

    @Override
    public SExp getValueSExp(SExp sexp) {
        return ((SList)sexp).getSparts()[position -1];
    }

    @Override
    public SExp genSexpFromSexp(SExp sexp)
        throws IllegalAccessException,
            InvocationTargetException,
            NoSuchMethodException
    {
        return sexp;
    }
}
