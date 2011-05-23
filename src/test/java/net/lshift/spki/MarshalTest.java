package net.lshift.spki;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.Create.list;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class MarshalTest {
    @Test
    public void marshalTest() throws IOException {
        byte[] bytes = "(4:test26:abcdefghijklmnopqrstuvwxyz5:123455::: ::)".getBytes(Constants.ASCII);
        Sexp struct = list("test", atom("abcdefghijklmnopqrstuvwxyz"), atom("12345"), atom(":: ::"));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Marshal.marshal(new CanonicalSpkiOutputStream(baos), struct);
        assertArrayEquals(bytes, baos.toByteArray());
    }

    @Test
    public void unmarshalTest() throws ParseException, IOException {
        byte[] bytes = "(4:test26:abcdefghijklmnopqrstuvwxyz5:123455::: ::)".getBytes(Constants.ASCII);
        Sexp struct = list("test", atom("abcdefghijklmnopqrstuvwxyz"), atom("12345"), atom(":: ::"));
        assertEquals(struct, Marshal.unmarshal(
            new CanonicalSpkiInputStream(
                new ByteArrayInputStream(bytes))));
    }
}
