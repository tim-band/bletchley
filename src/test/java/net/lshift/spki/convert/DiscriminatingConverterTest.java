package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.list;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.sexpform.Sexp;

import org.junit.Test;

public class DiscriminatingConverterTest
{
    @Test
    public void testAssertDistinguishesExampleClasses() {
        assertFalse((new ImplementingClass())
            .equals(new OtherImplementingClass()));
    }

    @Test
    public void canConvertSexpToImplementingClass()
        throws ParseException,
            IOException
    {
        assertEquals(new ImplementingClass(),
            ConvertUtils.read(Interface.class,
                ConvertTestHelper.toConvert(
                    list("implementing-class"))));
    }

    @Test
    public void canConvertSexpToOtherImplementingClass()
        throws ParseException,
            IOException
    {
        assertEquals(new OtherImplementingClass(),
            ConvertUtils.read(Interface.class,
                ConvertTestHelper.toConvert(
                    list("other-implementing-class"))));
    }

    @Test
    public void canConvertImplementingClassToSexp() throws IOException {
        byte[] expected = ConvertUtils.toBytes(Sexp.class,
            list("implementing-class"));
        byte[] actual = ConvertUtils.toBytes(Interface.class,
            new ImplementingClass());
        assertThat(actual, is(expected));
    }
}
