package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.list;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;

import org.junit.Test;

public class DiscriminatingConverterTest extends UsesConverting
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
            ConvertUtils.read(getConverting(), Interface.class,
                ConvertTestHelper.toConvert(
                    list("implementing-class"))));
    }

    @Test
    public void canConvertSexpToOtherImplementingClass()
        throws IOException, InvalidInputException
    {
        assertEquals(new OtherImplementingClass(),
            ConvertUtils.read(getConverting(), Interface.class,
                ConvertTestHelper.toConvert(
                    list("other-implementing-class"))));
    }

    @Test
    public void canConvertImplementingClassToSexp() {
        final byte[] expected = ConvertUtils.toBytes(list("implementing-class"));
        final byte[] actual = ConvertUtils.toBytes(new ImplementingClass());
        assertThat(actual, is(expected));
    }

    @Test
    public void canHandleLateClass() throws InvalidInputException {
        Converting cextra = getConverting().extend(LateImplementingClass.class);
        final LateImplementingClass obj = new LateImplementingClass();
        final byte[] bytes = ConvertUtils.toBytes(obj);
        final Interface res = ConvertUtils.fromBytes(cextra, Interface.class, bytes);
        assertEquals(obj, res);
    }
}
