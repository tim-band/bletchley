package net.lshift.spki.convert;

import static net.lshift.spki.convert.ConvertTestHelper.toConvert;
import static net.lshift.spki.convert.ConvertUtils.read;
import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.sexpform.Slist;

import org.junit.Test;

public class NullableFieldTest {
    private static final Slist WITHOUT_OPTIONAL = list("with-optional",
            list("mandatory", atom("foo")));
    private static final Sexp WITH_OPTIONAL = list("with-optional",
            list("mandatory", atom("foo")),
            list("optional", atom("bar")));

    @Convert.ByName("with-optional")
    public static class WithOptional {
        public final String mandatory;
        @Convert.Nullable
        public final String optional;

        public WithOptional(String mandatory, String optional) {
            super();
            this.mandatory = mandatory;
            this.optional = optional;
        }
    }

    @Test
    public void testAllStillWorks() throws IOException, InvalidInputException {
        WithOptional res = read(WithOptional.class,
                toConvert(WITH_OPTIONAL));
        assertEquals("foo", res.mandatory);
        assertEquals("bar", res.optional);
    }

    @Test(expected=InvalidInputException.class)
    public void testMandatoryIsMandatory() throws IOException, InvalidInputException {
        read(WithOptional.class, toConvert(
                list("with-optional",
                        list("optional", atom("foo")))));
    }

    @Test
    public void testOptionalIsOptional() throws IOException, InvalidInputException {
        WithOptional res = read(WithOptional.class, toConvert(
                WITHOUT_OPTIONAL));
        assertEquals("foo", res.mandatory);
        assertEquals(null, res.optional);
    }

    @Test
    public void testRoundTripWorks() throws IOException, InvalidInputException {
        testRoundTripWorks(WITH_OPTIONAL);
        testRoundTripWorks(WITHOUT_OPTIONAL);
    }

    private static void testRoundTripWorks(Sexp sexp) throws IOException, InvalidInputException {
        byte[] direct = ConvertUtils.toBytes(Sexp.class, sexp);
        byte[] indirect = ConvertUtils.toBytes(WithOptional.class,
                read(WithOptional.class, toConvert(sexp)));
        assertArrayEquals(direct, indirect);
    }
}
