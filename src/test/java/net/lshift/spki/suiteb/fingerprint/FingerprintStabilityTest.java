package net.lshift.spki.suiteb.fingerprint;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import net.lshift.spki.sexpform.Sexp;

import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class FingerprintStabilityTest {
    private static class TestPair {
        private final Sexp test;
        private final String fingerprint;

        public TestPair(Sexp test, String fingerprint) {
            super();
            this.test = test;
            this.fingerprint = fingerprint;
        }

        public Sexp getTest() {
            return test;
        }

        public String getFingerprint() {
            return fingerprint;
        }
    }

    @DataPoints
    public static TestPair[] data() {
        return new TestPair[] {
            new TestPair(atom(""),
                "yet-heaps-geo/owner-jp-siege/serve-jesus-gordon/emma-maybe-havoc/oaf-glory-orbs"),
            new TestPair(atom("hello"),
                "sutton-awful-sperm/welch-reek-tyke/hhhh-nag-brady/dn-fatal-mn/jive-text-jp"),
            new TestPair(list("hello"),
                "says-habit-morsel/lice-mouth-take/vomit-waste-sleds/fled-skunk-wino/gu-twin-cock"),
            new TestPair(list("hello", atom("there")),
                "bow-owl-dues/peak-check-eli/bang-posse-fogy/jewel-ages-sum/clumsy-flirt-like"),
        };
    }

    @Theory
    public void theoryFingerprintsAreStable(TestPair pair) {
        assertThat(
            FingerprintUtils.getFingerprint(Sexp.class, pair.getTest()),
            is(pair.getFingerprint()));
    }
}
