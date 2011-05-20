package net.lshift.spki;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.Create.list;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class MarshalTest {
    @Test
    public void marshalTest() {
        byte[] bytes = "(4:test26:abcdefghijklmnopqrstuvwxyz5:123455::: ::)".getBytes(Constants.UTF8);
        Sexp struct = list("test", atom("abcdefghijklmnopqrstuvwxyz"), atom("12345"), atom(":: ::"));
        assertArrayEquals(bytes, Marshal.marshal(struct));
    }

    @Test
    public void unmarshalTest() throws ParseException {
        byte[] bytes = "(4:test26:abcdefghijklmnopqrstuvwxyz5:123455::: ::)".getBytes(Constants.UTF8);
        Sexp struct = list("test", atom("abcdefghijklmnopqrstuvwxyz"), atom("12345"), atom(":: ::"));
        assertEquals(struct, Marshal.unmarshal(bytes));
    }
}
