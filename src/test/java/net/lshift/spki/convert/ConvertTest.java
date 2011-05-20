package net.lshift.spki.convert;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import net.lshift.spki.ParseException;

import org.junit.Test;

public class ConvertTest
{
    @Test
    public void convertTest() throws ParseException {
        ConvertExample test = new ConvertExample(
            BigInteger.valueOf(3), BigInteger.valueOf(17));
        byte[] bytes = ConvertUtils.toBytes(ConvertExample.class, test);
        //PrettyPrinter.prettyPrint(System.out, sexp);
        ConvertExample changeBack = ConvertUtils.fromBytes(
            ConvertExample.class, bytes);
        assertEquals(test, changeBack);
    }
}
