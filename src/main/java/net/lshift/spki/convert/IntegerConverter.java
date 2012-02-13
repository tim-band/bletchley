package net.lshift.spki.convert;

import java.math.BigInteger;

import net.lshift.spki.InvalidInputException;

public class IntegerConverter
    extends StepConverter<Integer,BigInteger> {

    @Override public Class<Integer> getResultClass() { return Integer.class; }

    @Override protected Class<BigInteger> getStepClass() { return BigInteger.class; }

    @Override
    protected Integer stepOut(final BigInteger s)
        throws InvalidInputException {
        return s.intValue();
    }

    @Override
    protected BigInteger stepIn(final Integer o) {
        return BigInteger.valueOf(o);
    }
}
