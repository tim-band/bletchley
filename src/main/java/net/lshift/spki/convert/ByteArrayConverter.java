package net.lshift.spki.convert;

import net.lshift.spki.Create;
import net.lshift.spki.SExp;

/**
 * Convert between a byte[] and a SExp
 */
public class ByteArrayConverter
    implements Converter<byte[]>
{
    @Override
    public byte[] fromSexp(SExp sexp)
    {
        return ConvertUtils.toBytes(sexp);
    }

    @Override
    public SExp toSexp(byte[] o)
    {
        return Create.atom(o);
    }
}
