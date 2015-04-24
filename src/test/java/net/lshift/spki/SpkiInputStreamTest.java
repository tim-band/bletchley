package net.lshift.spki;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;
import static net.lshift.spki.SpkiInputStream.TokenType.CLOSEPAREN;
import static net.lshift.spki.SpkiInputStream.TokenType.EOF;
import static net.lshift.spki.SpkiInputStream.TokenType.OPENPAREN;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

public abstract class SpkiInputStreamTest {
    public SpkiInputStream sis;

    public static byte[] s(final String string) {
        return string.getBytes(StandardCharsets.US_ASCII);
    }

    public void setInput(final byte [] bytes) {
        setInput(new ByteArrayInputStream(bytes));
    }

    protected abstract void setInput(InputStream inputStream);

    public SpkiInputStreamTest() {
        super();
    }

    public void setInput(final String string) {
        setInput(s(string));
    }

    @Test
    public void getAtom()
        throws IOException, ParseException {
        setInput("3:foo");
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("foo")));
        assertThat(sis.next(), is(EOF));
    }

    @Test
    public void getEmptyAtom()
        throws IOException, ParseException {
        setInput("0:");
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("")));
        assertThat(sis.next(), is(EOF));
    }

    @Test
    public void getLongerAtom()
        throws IOException, ParseException {
        setInput("12:foodfoodfood");
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("foodfoodfood")));
        assertThat(sis.next(), is(EOF));
    }

    @Test(expected = ParseException.class)
    public void catchOverflow()
        throws IOException, ParseException {
        setInput("4294967299:foo");
        sis.next();
        sis.atomBytes();
    }

    @Test(expected = ParseException.class)
    public void tooShortAtomCausesException()
        throws IOException, ParseException {
        setInput("3:fo");
        sis.next();
        sis.atomBytes();
    }

    @Test(expected = IllegalStateException.class)
    public void assertMustReadAtom()
        throws ParseException, IOException {
        setInput("3:foo");
        sis.next();
        sis.next();
    }

    @Test
    public void canReadOpenCloseParen()
        throws ParseException, IOException {
        setInput("(3:foo)");
        assertThat(sis.next(), is(OPENPAREN));
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("foo")));
        assertThat(sis.next(), is(CLOSEPAREN));
        assertThat(sis.next(), is(EOF));
    }

    @Test(expected = ParseException.class)
    public void assertNonDigitsFails()
        throws ParseException, IOException {
        setInput("34asdf");
        sis.next();
    }

    @Test(expected = IllegalStateException.class)
    public void assertDoesntRecover()
        throws ParseException, IOException {
        setInput("34a3:foo");
        try {
            sis.next();
        } catch (final ParseException e) {
            // ignore it
        }
        sis.atomBytes();
    }

    @Test(expected = OutOfMemoryError.class)
    public void assertMaxintWorks()
            throws ParseException, IOException {
        setInput("2147483647:foo");
        assertThat(sis.next(), is(ATOM));
        sis.atomBytes();
    }

    @Test(expected = ParseException.class)
    public void assertOverflowFails()
            throws ParseException, IOException {
        setInput("2147483648:foo");
        sis.next();
    }
}
