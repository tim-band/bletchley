package net.lshift.spki.convert;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.math.BigInteger;

import net.lshift.spki.ParseException;
import net.lshift.spki.SExp;

import org.junit.Test;

public class ConvertTest
{
    @Test
    public void convertTest() throws ParseException, IOException {
        ConvertExample test = new ConvertExample(
            BigInteger.valueOf(3), BigInteger.valueOf(17));
        SExp sexp = Convert.toSExp(test);
        //PrettyPrinter.prettyPrint(System.out, sexp);
        ConvertExample changeBack = Convert.fromSExp(
            ConvertExample.class, sexp);
        assertEquals(test, changeBack);
    }
}
