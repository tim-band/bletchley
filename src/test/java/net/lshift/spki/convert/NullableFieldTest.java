package net.lshift.spki.convert;

import static net.lshift.spki.convert.ConvertTestHelper.toConvert;
import static net.lshift.spki.convert.ConvertUtils.read;
import static net.lshift.spki.convert.ConvertUtils.toBytes;
import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

import org.junit.Test;

public class NullableFieldTest extends UsesCatalog {
    @Convert.ByName("with-optional")
    public static class WithOptional extends SexpBacked {
        public final String mandatory;
        @Convert.Nullable
        public final String optional;

        public WithOptional(final String mandatory, final String optional) {
            super();
            this.mandatory = mandatory;
            this.optional = optional;
        }
    }

    @Test
    public void roundTripWorks() throws IOException, InvalidInputException {
        testRoundTripWorks(new WithOptional("foo", "bar"),
                list("with-optional",
                        list("mandatory", atom("foo")),
                        list("optional", atom("bar"))));
        testRoundTripWorks(new WithOptional("foo", null),
                list("with-optional",
                        list("mandatory", atom("foo"))));
    }

    private void testRoundTripWorks(final WithOptional withOptional, final Sexp sexp) throws IOException, InvalidInputException {
        final WithOptional read = read(getReadInfo(), WithOptional.class, toConvert(sexp));
        assertEquals(withOptional.mandatory, read.mandatory);
        assertEquals(withOptional.optional, read.optional);
        final byte[] direct = toBytes(sexp);
        final byte[] indirect = toBytes(withOptional);
        assertArrayEquals(direct, indirect);
    }

    @Test(expected=InvalidInputException.class)
    public void mandatoryIsMandatory() throws IOException, InvalidInputException {
        read(getReadInfo(), WithOptional.class, toConvert(
                list("with-optional",
                        list("optional", atom("foo")))));
    }

    @Test(expected=NullPointerException.class)
    public void mandatoryCannotBeNull() {
        toBytes(new WithOptional(null, "bar"));
    }
}
