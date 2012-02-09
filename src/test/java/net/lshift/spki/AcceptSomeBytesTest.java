package net.lshift.spki;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Test;

public class AcceptSomeBytesTest {

    private void testAccepter(
        AcceptSomeBytes accepter,
        String input,
        String accepted,
        int left) throws IOException {
        ByteArrayInputStream is = new ByteArrayInputStream(
            input.getBytes(Constants.ASCII));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int dropped = accepter.accept(out, is);
        assertArrayEquals(accepted.getBytes(Constants.ASCII),
            out.toByteArray());
        assertEquals(left, dropped);
    }

    @Test
    public void acceptsOnlyPrintable() throws IOException {
        testAccepter(AcceptSomeBytes.PRINTABLES, "Hi!\n", "Hi!", '\n');
    }

    @Test
    public void stopsOnEof() throws IOException {
        testAccepter(AcceptSomeBytes.PRINTABLES, "foo", "foo", -1);
    }

    @Test
    public void stopsOnQuote() throws IOException {
        testAccepter(AcceptSomeBytes.STRING, "foo\"", "foo", '\"');
    }

    @Test
    public void stopsOnBackslash() throws IOException {
        testAccepter(AcceptSomeBytes.STRING, "foo\\", "foo", '\\');
    }

    @Test
    public void hex() throws IOException {
        testAccepter(AcceptSomeBytes.HEX, "f00f#", "f00f", '#');
    }

    @Test
    public void base64() throws IOException {
        testAccepter(AcceptSomeBytes.BASE64, "TWFuI+0/=|", "TWFuI+0/=", '|');
    }
}
