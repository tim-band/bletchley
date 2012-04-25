package net.lshift.spki;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.sexpform.Sexp;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class PrettyPrinterTest {
    private static final boolean WRITE_TEST_OUTPUT = false;
    private static class TestPair {
        private final String resourceName;
        private final Sexp sexp;

        public TestPair(final String resourceName, final Sexp sexp) {
            super();
            this.resourceName = resourceName;
            this.sexp = sexp;
        }

        public TestPair(final int i, final Sexp sexp) {
            this(Integer.toString(i) + ".spki", sexp);
        }

        public Sexp getSexp() { return sexp; }

        public String getResourceName() { return resourceName; }

        public InputStream getResourceAsStream() {
            return PrettyPrinterTest.class.getResourceAsStream(
                "_PrettyPrinterTest/" + getResourceName());
        }
    }

    @DataPoints
    public static TestPair[] data() {
        int counter = 1;
        return new TestPair[] {
            new TestPair(counter++, atom("foo")),
            new TestPair(counter++, list("foo")),
            new TestPair(counter++, list("foo", list("bar", atom("baz")), atom("foof"))),
            new TestPair(counter++, list("foo",  atom("baz"))),
            new TestPair(counter++, list("fo\"o",  atom("baz"))),
            new TestPair(counter++, list("fo-o",  atom("baz"))),
            new TestPair(counter++, list("foo bar",  atom("baz"))),
            new TestPair(counter++, list("\0x80fsssssssssssssoo bar",  atom("baz"))),
        };
    }

    @Theory
    public void theoryPrettyPrintingIsStable(final TestPair pair) throws IOException {
        final String prettyPrinted
            = ConvertUtils.prettyPrint(pair.getSexp());
        assertThat(prettyPrinted,
            is(IOUtils.toString(pair.getResourceAsStream())));
    }

    @Theory
    public void theoryCanParsePrettyPrintedData(final TestPair pair)
                    throws IOException, InvalidInputException {
        final Sexp parsed = ConvertUtils.readAdvanced(Sexp.class, pair.getResourceAsStream());
        assertThat(parsed, is(pair.getSexp()));
    }

    @Test
    public void handleWriteTestOutput() throws IOException {
        if (WRITE_TEST_OUTPUT) {
            for (final TestPair pair : data()) {
                final String prettyPrinted = ConvertUtils.prettyPrint(
                    pair.getSexp());
                final FileOutputStream out
                    = new FileOutputStream("/tmp/out/" + pair.getResourceName());
                IOUtils.write(prettyPrinted, out);
                out.close();
            }
        }
        assertFalse(WRITE_TEST_OUTPUT);
    }
}
