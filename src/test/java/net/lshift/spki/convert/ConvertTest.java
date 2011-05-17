package net.lshift.spki.convert;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import net.lshift.spki.SExp;

import org.junit.Test;

public class ConvertTest
{
    @Test
    public void convertTest() {
        ConvertExample test = new ConvertExample(
            BigInteger.valueOf(3), BigInteger.valueOf(17));
        SExp sexp = Convert.toSExp(ConvertExample.class, test);
        //PrettyPrinter.prettyPrint(System.out, sexp);
        ConvertExample changeBack = Convert.fromSExp(
            ConvertExample.class, sexp);
        assertEquals(test, changeBack);
    }
}
