package net.lshift.spki.convert;

import net.lshift.spki.SExp;
import net.lshift.spki.SList;

/**
 * SExp converter that lists the bean fields in a fixed order.
 */
public class PositionBeanConverter<T>
    extends BeanFieldConverter<T>
{
    public PositionBeanConverter(Class<T> clazz)
    {
        super(clazz);
    }

    @Override
    protected SExp fieldToSexp(FieldConvertInfo fieldConvertInfo, SExp sexp)
    {
        return sexp;
    }

    @Override
    protected SExp getSExp(
        FieldConvertInfo fieldConvertInfo,
        int i,
        SList slist)
    {
        return slist.getSparts()[i];
    }
}
