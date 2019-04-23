package net.lshift.spki.convert;

import java.math.BigInteger;

import net.lshift.spki.InvalidInputException;

public class IntegerConverter
        extends StepConverter<Integer, BigInteger> {

    public IntegerConverter() {
        super(Integer.class, BigInteger.class);
    }

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
