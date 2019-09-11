package net.lshift.spki.convert;

import java.math.BigInteger;

import net.lshift.spki.InvalidInputException;

public class IntegerConverter {

    private IntegerConverter() { }

    public static Integer stepOut(final BigInteger s)
        throws InvalidInputException {
        return s.intValue();
    }

    public static BigInteger stepIn(final Integer o) {
        return BigInteger.valueOf(o);
    }
}
