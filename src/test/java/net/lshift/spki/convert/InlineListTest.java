package net.lshift.spki.convert;

import static net.lshift.spki.convert.ConvertTestHelper.toConvert;
import static net.lshift.spki.convert.ConvertUtils.read;
import static net.lshift.spki.convert.ConvertUtils.toBytes;
import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

import org.junit.Test;

public class InlineListTest {
    @Convert.ByName("uses-inline-list")
    public static class UsesInlineList {
        @Convert.InlineList
        public final List<String> inlineList;

        public UsesInlineList(List<String> inlineList) {
            super();
            this.inlineList = inlineList;
        }
    }

    @Test
    public void roundTripWorks() throws IOException, InvalidInputException {
        testRoundTripWorks(new UsesInlineList(Arrays.asList("foo", "bar")),
            list("uses-inline-list",
                    list("inline-list", atom("foo"), atom("bar"))));
    }

    private static void testRoundTripWorks(final UsesInlineList obj, final Sexp sexp) throws IOException, InvalidInputException {
        final UsesInlineList read = read(UsesInlineList.class, toConvert(sexp));
        assertEquals(obj.inlineList, read.inlineList);
        final byte[] direct = toBytes(Sexp.class, sexp);
        final byte[] indirect = toBytes(UsesInlineList.class, obj);
        assertArrayEquals(direct, indirect);
    }
}
