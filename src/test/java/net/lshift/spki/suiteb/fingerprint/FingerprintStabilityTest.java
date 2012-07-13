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

        public TestPair(final Sexp test, final String fingerprint) {
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
                "word-shots-term/boils-hyde-dish/cajun-vs-zw/doubt-them-cry/torn-accuse-facile"),
            new TestPair(atom("hello"),
                "ire-bh-marks/sol-carat-norway/hhhh-bushy-rufus/sara-grout-ouija/pencil-leda-yyyy"),
            new TestPair(list("hello"),
                "bk-crank-award/moore-buyer-gil/vie-gauge-byline/e-gl-tut/irvin-lcd-bowed"),
            new TestPair(list("hello", atom("there")),
                "nails-whine-led/ah-levis-endow/xr-porn-carpet/posse-node-wear/waxy-locks-root"),
        };
    }

    @Theory
    public void theoryFingerprintsAreStable(final TestPair pair) {
        assertThat(
            FingerprintUtils.getFingerprint(pair.getTest()),
            is(pair.getFingerprint()));
    }
}
