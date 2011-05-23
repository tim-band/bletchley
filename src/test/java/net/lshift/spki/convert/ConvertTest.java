package net.lshift.spki.convert;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.Create.list;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import net.lshift.spki.ParseException;
import net.lshift.spki.Sexp;

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

    @Test
    public void sexpTest() throws ParseException {
        byte[] bytes = ConvertUtils.bytes("(3:foo)");
        assertEquals(list(atom("foo")),
            ConvertUtils.fromBytes(Sexp.class, bytes));
    }

    @Test(expected=ParseException.class)
    public void extraBytesMeansParseException() throws ParseException {
        byte[] bytes = ConvertUtils.bytes("(3:foo)1:o");
        ConvertUtils.fromBytes(Sexp.class, bytes);
    }
}
