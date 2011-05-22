package net.lshift.spki;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.junit.Test;

public class SpkiInputStreamTest
{
    public SpkiInputStream sis;

    public void setInput(byte [] bytes) {
        sis = new CanonicalSpkiInputStream(
            new ByteArrayInputStream(bytes));
    }

    public static byte[] s(String string) {
        return string.getBytes(Constants.ASCII);
    }

    public void setInput(String string) {
        setInput(s(string));
    }

    @Test
    public void getAtom() throws IOException, ParseException {
        setInput("3:foo");
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("foo")));
    }

    @Test
    public void getLongerAtom() throws IOException, ParseException {
        setInput("12:foodfoodfood");
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("foodfoodfood")));
    }

    @Test(expected=ParseException.class)
    public void catchOverflow() throws IOException, ParseException {
        setInput("4294967299:foo");
        sis.next();
        sis.atomBytes();
    }

    @Test(expected=ParseException.class)
    public void tooShortAtomCausesException() throws IOException, ParseException {
        setInput("3:fo");
        sis.next();
        sis.atomBytes();
    }

    @Test(expected=IllegalStateException.class)
    public void assertMustReadAtom() throws ParseException, IOException {
        setInput("3:foo");
        sis.next();
        sis.next();
    }

    @Test
    public void assertAtomIsOKWhenNextIsAtom() throws ParseException, IOException {
        setInput("3:foo");
        sis.nextAssertType(ATOM);
    }

    @Test(expected=ParseException.class)
    public void assertAtomFailsWhenNextIsNotAtom() throws ParseException, IOException {
        setInput("(3:foo)");
        sis.nextAssertType(ATOM);
    }

    @Test(expected=ParseException.class)
    public void assertNonDigitsFails() throws ParseException, IOException {
        setInput("34asdf");
        sis.next();
    }

    @Test(expected=IllegalStateException.class)
    public void assertDoesntRecover() throws ParseException, IOException {
        setInput("34a3:foo");
        try {
            sis.next();
        } catch (ParseException e) {
            // ignore it
        }
        sis.atomBytes();
    }
}
