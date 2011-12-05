package net.lshift.spki;

import static net.lshift.spki.SpkiInputStream.TokenType.ATOM;
import static net.lshift.spki.SpkiInputStream.TokenType.CLOSEPAREN;
import static net.lshift.spki.SpkiInputStream.TokenType.EOF;
import static net.lshift.spki.SpkiInputStream.TokenType.OPENPAREN;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class AdvancedSpkiInputStreamTest extends SpkiInputStreamTest
{
    @Override
    protected void setInput(InputStream inputStream) {
        sis = new AdvancedSpkiInputStream(inputStream);
    }

    @Test
    public void getBareAtom()
        throws IOException, ParseException {
        setInput("foo");
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("foo")));
        assertThat(sis.next(), is(EOF));
    }

    @Test
    public void getQuotedString()
        throws IOException, ParseException {
        setInput("\"foo\"");
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("foo")));
        assertThat(sis.next(), is(EOF));
    }

    @Test
    public void canStillReadOpenCloseParen()
        throws ParseException, IOException {
        setInput(" ( foo ) ");
        assertThat(sis.next(), is(OPENPAREN));
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("foo")));
        assertThat(sis.next(), is(CLOSEPAREN));
        assertThat(sis.next(), is(EOF));
    }

    @Test
    public void handlePushbackProperly()
        throws ParseException, IOException {
        setInput(" ( foo(bar) ) ");
        assertThat(sis.next(), is(OPENPAREN));
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("foo")));
        assertThat(sis.next(), is(OPENPAREN));
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("bar")));
        assertThat(sis.next(), is(CLOSEPAREN));
        assertThat(sis.next(), is(CLOSEPAREN));
        assertThat(sis.next(), is(EOF));
    }

    @Test
    public void readHexExpression()
        throws IOException, ParseException {
        setInput("#21#");
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("!")));
        assertThat(sis.next(), is(EOF));
    }

    @Test
    public void readBase64Expression()
        throws IOException, ParseException {
        setInput("|TWFu|");
        assertThat(sis.next(), is(ATOM));
        assertThat(sis.atomBytes(), is(s("Man")));
        assertThat(sis.next(), is(EOF));
    }

    @Test
    public void HexIgnoresSpaces() {
        assertThat(Hex.decode("  4 d 6 1 6 E "),
            is(s("Man")));
    }

//    @Test
//    public void Base64IgnoresSpaces() {
//        assertThat(Base64.decode("TWFu"),
//            is(s("Man")));
//        assertThat(Base64.decode(" T W F u TWFu"),
//            is(s("ManMan")));
//        assertThat(Base64.decode(" T W F u "), // fails
//            is(s("Man")));
//    }
}
