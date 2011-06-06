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

@SuppressWarnings("unchecked")
public class DiscriminatingConverterTest
{
    // http://stackoverflow.com/questions/1445233
    // Is it possible to solve the “A generic array of T is created for a
    // varargs parameter” compiler warning?
    Converter<Interface> converter
        = new DiscriminatingConverter<Interface>(
                        ImplementingClass.class, OtherImplementingClass.class);

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
            converter.read(ConvertTestHelper.toConvert(
                list("implementing-class"))));
    }

    @Test
    public void canConvertSexpToOtherImplementingClass()
        throws ParseException,
            IOException
    {
        assertEquals(new OtherImplementingClass(),
            converter.read(ConvertTestHelper.toConvert(
                list("other-implementing-class"))));
    }

    @Test
    public void canConvertImplementingClassToSexp() throws IOException {
        byte[] expected = ConvertUtils.toBytes(Sexp.class,
            list("implementing-class"));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ConvertOutputStream conv = new ConvertOutputStream(baos);
        converter.write(conv, new ImplementingClass());
        assertThat(baos.toByteArray(), is(expected));
    }
}
