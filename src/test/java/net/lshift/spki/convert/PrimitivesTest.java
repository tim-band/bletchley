package net.lshift.spki.convert;

import static org.junit.Assert.assertEquals;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.ActionType;

import org.junit.Test;

public class PrimitivesTest {
    @Convert.ByPosition(fields = { "b", "i" }, name = "primitive")
    public static class PrimitivesExample implements ActionType {
        public final boolean b;
        public final int i;
        public PrimitivesExample(boolean b, int i) {
            this.b = b;
            this.i = i;
        }
    }

    @Test
    public void testConvert() throws InvalidInputException {
        PrimitivesExample a = new PrimitivesExample(true, 314);
        PrimitivesExample b = ConvertUtils.fromBytes(
                ConverterCatalog.BASE.extend(PrimitivesExample.class), 
                PrimitivesExample.class, 
                ConvertUtils.toBytes(a));
        assertEquals(a.b, b.b);
        assertEquals(a.i, b.i);
    }

    @Convert.ByPosition(fields = { "é" }, name = "primitive-non-ascii")
    public static class PrimitivesExampleWithNonasciiFields implements ActionType {
        public final boolean é;
        public PrimitivesExampleWithNonasciiFields(boolean e) {
            this.é = e;
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConvertNonascii() throws Exception {
        PrimitivesExampleWithNonasciiFields a = new PrimitivesExampleWithNonasciiFields(true);
        PrimitivesExampleWithNonasciiFields b = ConvertUtils.fromBytes(
                ConverterCatalog.BASE.extend(PrimitivesExampleWithNonasciiFields.class),
                PrimitivesExampleWithNonasciiFields.class,
                ConvertUtils.toBytes(a));
        assertEquals(a.é, b.é);
    }
}
