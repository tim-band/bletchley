package net.lshift.spki.convert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.Test;

import net.lshift.spki.CanonicalSpkiInputStream;
import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStreamTest;
import net.lshift.spki.convert.ConvertInputStream;

public class ConvertInputStreamTest
    extends SpkiInputStreamTest {

    @Override
    protected void setInput(InputStream inputStream) {
        sis = new ConvertInputStream(
            new CanonicalSpkiInputStream(inputStream));
    }

    @Test(expected = IllegalStateException.class)
    public void peekMustBeFollowedByNext() throws ParseException, IOException {
        ConvertInputStream testStream = new ConvertInputStream(
            new CanonicalSpkiInputStream(
                new ByteArrayInputStream(
                    ConvertUtils.bytes("3:foo"))));
        testStream.peek();
        testStream.atomBytes();
    }
}
