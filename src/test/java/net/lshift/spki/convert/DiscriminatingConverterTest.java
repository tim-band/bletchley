package net.lshift.spki.convert;

import static net.lshift.spki.Create.list;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.io.IOException;

import net.lshift.spki.Constants;
import net.lshift.spki.SpkiOutputStream;

import org.junit.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;

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
    public void canConvertImplementingClassToSexp() throws IOException {
        SpkiOutputStream stream = mock(SpkiOutputStream.class);
        ConvertOutputStream conv = new ConvertOutputStream(stream);
        converter.write(conv, new ImplementingClass());
        InOrder inOrder = Mockito.inOrder(stream);
        inOrder.verify(stream).beginSexp();
        inOrder.verify(stream).atom(
            "implementing-class".getBytes(Constants.ASCII));
        inOrder.verify(stream).endSexp();
        verifyNoMoreInteractions(stream);
    }
}
