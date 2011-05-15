package net.lshift.spki.convert;

import java.math.BigInteger;

import net.lshift.spki.Create;
import net.lshift.spki.SExp;

public class BigIntegerConverter
    implements Converter<BigInteger>
{
    @Override
    public BigInteger fromSexp(SExp sexp)
    {
        return new BigInteger(ConvertUtils.toBytes(sexp));
    }

    @Override
    public SExp toSexp(BigInteger o)
    {
        return Create.atom(o.toByteArray());
    }
}
