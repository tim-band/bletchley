package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.math.BigInteger;
import java.util.UUID;

import net.lshift.spki.Constants;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.sexpform.Sexp;

import org.junit.Test;

public class ConvertTest extends ResetsRegistry
{
    @Test
    public void convertTest() throws InvalidInputException, IOException {
        final ConvertExample test = new ConvertExample(
            BigInteger.valueOf(3), BigInteger.valueOf(17), "test");
        testExample(test);
    }

    private static void testExample(final ConvertExample test)
        throws InvalidInputException, IOException {
        testConanonicalConvert(test);
        testAdvancedConvert(test);
    }

    private static void testAdvancedConvert(ConvertExample test) throws IOException, InvalidInputException {
        ByteOpenable printed = new ByteOpenable();
        ConvertUtils.prettyPrint(ConvertExample.class, test, printed.write());
        ConvertUtils.prettyPrint(ConvertExample.class, test, System.out);
        final ConvertExample changeBack = ConvertUtils.readAdvanced(ConvertExample.class, printed.read());
        assertEquals(test, changeBack);
    }

    private static void testConanonicalConvert(final ConvertExample test)
        throws InvalidInputException {
        final byte[] bytes = ConvertUtils.toBytes(ConvertExample.class, test);
        final ConvertExample changeBack = ConvertUtils.fromBytes(
            ConvertExample.class, bytes);
        assertEquals(test, changeBack);
    }

    @Test
    public void convertHyphenTest() throws InvalidInputException, IOException {
        final ConvertExample test = new ConvertExample(
            BigInteger.valueOf(3), BigInteger.valueOf(17), "-");
        testExample(test);
    }

    @Test
    public void sexpTest() throws InvalidInputException {
        final byte[] bytes = ConvertUtils.bytes("(3:foo)");
        assertEquals(list("foo"),
            ConvertUtils.fromBytes(Sexp.class, bytes));
    }

    @Test(expected=ConvertException.class)
    public void extraBytesMeansParseException() throws InvalidInputException {
        final byte[] bytes = ConvertUtils.bytes("(3:foo)1:o");
        ConvertUtils.fromBytes(Sexp.class, bytes);
    }

    @Test
    public void marshalTest() {
        final byte[] bytes = "(4:test26:abcdefghijklmnopqrstuvwxyz5:123455::: ::)".getBytes(Constants.ASCII);
        final Sexp struct = list("test", atom("abcdefghijklmnopqrstuvwxyz"), atom("12345"), atom(":: ::"));
        assertArrayEquals(bytes, ConvertUtils.toBytes(Sexp.class, struct));
    }

    @Test
    public void unmarshalTest() throws InvalidInputException {
        final byte[] bytes = "(4:test26:abcdefghijklmnopqrstuvwxyz5:123455::: ::)".getBytes(Constants.ASCII);
        final Sexp struct = list("test", atom("abcdefghijklmnopqrstuvwxyz"), atom("12345"), atom(":: ::"));
        assertEquals(struct, ConvertUtils.fromBytes(Sexp.class, bytes));
    }

    @Test
    public void convertFromUUID() throws InvalidInputException {
        final String uidstring = "093fe929-3d5d-48f9-bb41-58a382de934f";
        final UUID uuid = UUID.fromString(uidstring);
        final byte[] uBytes = ConvertUtils.toBytes(UUID.class, uuid);
        assertEquals(atom(uidstring),
            ConvertUtils.fromBytes(Sexp.class, uBytes));
    }

    @Test
    public void convertToUUID() throws InvalidInputException {
        final String uidstring = "093fe929-3d5d-48f9-bb41-58a382de934f";
        final byte[] uBytes = ConvertUtils.toBytes(Sexp.class, atom(uidstring));
        assertEquals(UUID.fromString(uidstring),
            ConvertUtils.fromBytes(UUID.class, uBytes));
    }
}
