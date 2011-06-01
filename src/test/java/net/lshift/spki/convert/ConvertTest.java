package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import net.lshift.spki.Constants;
import net.lshift.spki.ParseException;
import net.lshift.spki.sexpform.Sexp;

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

    @Test
    public void marshalTest() {
        byte[] bytes = "(4:test26:abcdefghijklmnopqrstuvwxyz5:123455::: ::)".getBytes(Constants.ASCII);
        Sexp struct = list("test", atom("abcdefghijklmnopqrstuvwxyz"), atom("12345"), atom(":: ::"));
        assertArrayEquals(bytes, ConvertUtils.toBytes(Sexp.class, struct));
    }

    @Test
    public void unmarshalTest() throws ParseException {
        byte[] bytes = "(4:test26:abcdefghijklmnopqrstuvwxyz5:123455::: ::)".getBytes(Constants.ASCII);
        Sexp struct = list("test", atom("abcdefghijklmnopqrstuvwxyz"), atom("12345"), atom(":: ::"));
        assertEquals(struct, ConvertUtils.fromBytes(Sexp.class, bytes));
    }
}
