package net.lshift.spki.convert;

import static net.lshift.spki.Create.list;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

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
    public void canConvertSexpToImplementingClass() {
        assertEquals(new ImplementingClass(),
            converter.fromSexp(list("implementing-class")));
    }

    @Test
    public void canConvertSexpToOtherImplementingClass() {
        assertEquals(new OtherImplementingClass(),
            converter.fromSexp(list("other-implementing-class")));
    }

    @Test
    public void canConvertImplementingClassToSexp() {
        assertEquals(list("implementing-class"),
            converter.toSexp(new ImplementingClass()));
    }
}
