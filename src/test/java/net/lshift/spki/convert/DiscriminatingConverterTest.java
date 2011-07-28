package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.list;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

import org.junit.Test;

public class DiscriminatingConverterTest extends ResetsRegistry
{
    @Test
    public void testAssertDistinguishesExampleClasses() {
        assertFalse((new ImplementingClass())
            .equals(new OtherImplementingClass()));
    }

    @Test
    public void canConvertSexpToImplementingClass()
        throws IOException, InvalidInputException
    {
        assertEquals(new ImplementingClass(),
            ConvertUtils.read(Interface.class,
                ConvertTestHelper.toConvert(
                    list("implementing-class"))));
    }

    @Test
    public void canConvertSexpToOtherImplementingClass()
        throws IOException, InvalidInputException
    {
        assertEquals(new OtherImplementingClass(),
            ConvertUtils.read(Interface.class,
                ConvertTestHelper.toConvert(
                    list("other-implementing-class"))));
    }

    @Test
    public void canConvertImplementingClassToSexp() {
        final byte[] expected = ConvertUtils.toBytes(Sexp.class,
            list("implementing-class"));
        final byte[] actual = ConvertUtils.toBytes(Interface.class,
            new ImplementingClass());
        assertThat(actual, is(expected));
    }
}
