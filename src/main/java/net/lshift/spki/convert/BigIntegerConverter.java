package net.lshift.spki.convert;

import java.io.IOException;
import java.math.BigInteger;

import net.lshift.spki.Create;
import net.lshift.spki.Sexp;

/**
 * Convert between a BigInteger and a SExp
 */
public class BigIntegerConverter
    implements Converter<BigInteger>
{
    @Override
    public BigInteger fromSexp(Sexp sexp)
    {
        return new BigInteger(ConvertUtils.toBytes(sexp));
    }

    @Override
    public Sexp toSexp(BigInteger o)
    {
        return Create.atom(o.toByteArray());
    }

    @Override
    public void write(ConvertOutputStream out, BigInteger o) throws IOException
    {
        out.atom(o.toByteArray());
    }
}
