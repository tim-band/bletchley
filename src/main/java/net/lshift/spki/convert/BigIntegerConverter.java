package net.lshift.spki.convert;

import java.math.BigInteger;

import net.lshift.spki.InvalidInputException;

/**
 * Convert between a BigInteger and a SExp
 */
public class BigIntegerConverter
    extends ByteArrayStepConverter<BigInteger> {
    @Override
    public Class<BigInteger> getResultClass() {
        return BigInteger.class;
    }

    @Override
    protected BigInteger stepOut(byte[] s)
        throws InvalidInputException {
        return new BigInteger(s);
    }

    @Override
    protected byte[] stepIn(BigInteger o) {
        return o.toByteArray();
    }
}
