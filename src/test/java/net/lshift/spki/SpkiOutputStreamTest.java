package net.lshift.spki;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Test;

public class SpkiOutputStreamTest
{
    public ByteArrayOutputStream output = new ByteArrayOutputStream();
    public CanonicalSpkiOutputStream sos = new CanonicalSpkiOutputStream(output);

    public byte[] getOutput() {
        return output.toByteArray();
    }

    public static byte[] s(final String string) {
        return string.getBytes(Constants.ASCII);
    }

    @Test
    public void serializeAtom() throws IOException {
        sos.atom(s("foo"));
        sos.close();
        assertThat(getOutput(), is(s("3:foo")));
    }

    @Test
    public void serializeOneElementSexp() throws IOException {
        sos.beginSexp();
        sos.atom(s("foo"));
        sos.endSexp();
        sos.close();
        assertThat(getOutput(), is(s("(3:foo)")));
    }
}
