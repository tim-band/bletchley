package net.lshift.spki.convert;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.Create.list;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.util.UUID;

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

    @Test
    public void convertFromUUID() throws ParseException {
        final String uidstring = "093fe929-3d5d-48f9-bb41-58a382de934f";
        UUID uuid = UUID.fromString(uidstring);
        byte[] uBytes = ConvertUtils.toBytes(UUID.class, uuid);
        assertEquals(atom(uidstring),
            ConvertUtils.fromBytes(Sexp.class, uBytes));
    }

    @Test
    public void convertToUUID() throws ParseException {
        final String uidstring = "093fe929-3d5d-48f9-bb41-58a382de934f";
        byte[] uBytes = ConvertUtils.toBytes(Sexp.class, atom(uidstring));
        assertEquals(UUID.fromString(uidstring),
            ConvertUtils.fromBytes(UUID.class, uBytes));
    }
}
