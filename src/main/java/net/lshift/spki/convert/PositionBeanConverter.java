package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.Sexp;
import net.lshift.spki.Slist;

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
    protected Sexp fieldToSexp(FieldConvertInfo fieldConvertInfo, Sexp sexp)
    {
        return sexp;
    }

    @Override
    protected Sexp getSExp(
        FieldConvertInfo fieldConvertInfo,
        int i,
        Slist slist)
    {
        return slist.getSparts().get(i);
    }

    @Override
    protected void writeField(
        ConvertOutputStream out,
        FieldConvertInfo field,
        Object property)
        throws IOException
    {
        out.writeUnchecked(field.getType(), property);
    }
}
