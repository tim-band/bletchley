package net.lshift.spki.convert;

import static org.junit.Assert.assertEquals;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.ActionType;

import org.junit.Test;

public class PrimitivesTest {
    @Convert.ByPosition(fields = { "b", "i" }, name = "primitive")
    public static class PrimitivesExample extends SexpBacked implements ActionType {
        public final boolean b;
        public final int i;
        public PrimitivesExample(boolean b, int i) {
            super();
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
}
