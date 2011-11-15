package net.lshift.spki;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.InputStream;

import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.sexpform.Sexp;

import org.apache.commons.io.IOUtils;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class PrettyPrinterTest {
    private static class TestPair {
        private final Sexp sexp;
        //private final String resourceName;
        private final String prettyPrinted;

        public TestPair(Sexp sexp, String resourceName) throws IOException {
            super();
            this.sexp = sexp;
            //this.resourceName = resourceName;
            final InputStream resourceAsStream
                = PrettyPrinterTest.class.getResourceAsStream(
                    "_PrettyPrinterTest/" + resourceName);
            this.prettyPrinted = resourceAsStream == null ?  null :
                IOUtils.toString(resourceAsStream);
        }

        public Sexp getSexp() { return sexp; }

        //public String getResourceName() { return resourceName; }

        public String getPrettyPrinted() { return prettyPrinted; }
    }

    @DataPoints
    public static TestPair[] data() throws IOException {
        return new TestPair[] {
            new TestPair(atom("foo"), "1"),
            new TestPair(list("foo"), "2"),
            new TestPair(list("foo", list("bar", atom("baz")), atom("foof")), "3"),
            new TestPair(list("foo",  atom("baz")), "4"),
            new TestPair(list("fo\"o",  atom("baz")), "5"),
            new TestPair(list("fo-o",  atom("baz")), "6"),
            new TestPair(list("foo bar",  atom("baz")), "7"),
        };
    }

    @Theory
    public void theoryPrettyPrintingIsStable(TestPair pair) {
        final String prettyPrinted = ConvertUtils.prettyPrint(Sexp.class, pair.getSexp());
//        FileOutputStream out = new FileOutputStream("/tmp/out/" + pair.getResourceName());
//        IOUtils.write(prettyPrinted, out);
//        out.close();
        assertThat(
            prettyPrinted,
            is(pair.getPrettyPrinted()));
    }
}
