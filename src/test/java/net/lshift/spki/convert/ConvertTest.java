package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.util.UUID;

import net.lshift.spki.Constants;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

import org.junit.Test;

public class ConvertTest extends UsesConverting
{
    @Test
    public void convertTest() throws InvalidInputException {
        final ConvertExample test = new ConvertExample(
            BigInteger.valueOf(3), BigInteger.valueOf(17));
        final byte[] bytes = ConvertUtils.toBytes(test);
        //PrettyPrinter.prettyPrint(System.out, sexp);
        final ConvertExample changeBack = ConvertUtils.fromBytes(getConverting(),
            ConvertExample.class, bytes);
        assertEquals(test, changeBack);
    }

    @Test
    public void sexpTest() throws InvalidInputException {
        final byte[] bytes = ConvertUtils.bytes("(3:foo)");
        assertEquals(list("foo"),
            ConvertUtils.fromBytes(getConverting(), Sexp.class, bytes));
    }

    @Test(expected=ConvertException.class)
    public void extraBytesMeansParseException() throws InvalidInputException {
        final byte[] bytes = ConvertUtils.bytes("(3:foo)1:o");
        ConvertUtils.fromBytes(getConverting(), Sexp.class, bytes);
    }

    @Test
    public void marshalTest() {
        final byte[] bytes = "(4:test26:abcdefghijklmnopqrstuvwxyz5:123455::: ::)".getBytes(Constants.ASCII);
        final Sexp struct = list("test", atom("abcdefghijklmnopqrstuvwxyz"), atom("12345"), atom(":: ::"));
        assertArrayEquals(bytes, ConvertUtils.toBytes(struct));
    }

    @Test
    public void unmarshalTest() throws InvalidInputException {
        final byte[] bytes = "(4:test26:abcdefghijklmnopqrstuvwxyz5:123455::: ::)".getBytes(Constants.ASCII);
        final Sexp struct = list("test", atom("abcdefghijklmnopqrstuvwxyz"), atom("12345"), atom(":: ::"));
        assertEquals(struct, ConvertUtils.fromBytes(getConverting(), Sexp.class, bytes));
    }

    @Test
    public void convertFromUUID() {
        final String uidstring = "093fe929-3d5d-48f9-bb41-58a382de934f";
        final UUID uuid = UUID.fromString(uidstring);
        final Sexp uBytes = Registry.getConverter(UUID.class).write(uuid);
        assertEquals(atom(uidstring), uBytes);
    }

    @Test
    public void convertToUUID() throws InvalidInputException {
        final String uidstring = "093fe929-3d5d-48f9-bb41-58a382de934f";
        final byte[] uBytes = ConvertUtils.toBytes(atom(uidstring));
        assertEquals(UUID.fromString(uidstring),
            ConvertUtils.fromBytes(getConverting(), UUID.class, uBytes));
    }
}
