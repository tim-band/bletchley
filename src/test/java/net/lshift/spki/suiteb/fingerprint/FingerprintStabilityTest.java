package net.lshift.spki.suiteb.fingerprint;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;

import net.lshift.bletchley.suiteb.proto.SimpleMessageProto.SimpleMessage;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.SequenceItem;

@RunWith(Theories.class)
public class FingerprintStabilityTest {

    private static class TestPair {
        private final SequenceItem test;
        private final String fingerprint;

        public TestPair(final SequenceItem test, final String fingerprint) {
            this.test = test;
            this.fingerprint = fingerprint;
        }

        public SequenceItem getTest() {
            return test;
        }

        public String getFingerprint() {
            return fingerprint;
        }
    }

    @DataPoints
    public static TestPair[] data() {
        return new TestPair[] {
            new TestPair(message(""),
                "cheat-hoot-reads/hwy-vexed-cb/jm-px-mask/emits-books-wall/pain-skid-jolt"),
            new TestPair(message("hello"),
                "honey-knots-exert/dodo-irons-lenny/third-ale-brief/yelp-burns-essay/score-humid-bella")
        };
    }

    private static Action message(String text) {
        return new Action(Any.pack(SimpleMessage.newBuilder().setType("").setContent(ByteString.copyFromUtf8(text)).build()));
    }

    @Theory
    public void theoryFingerprintsAreStable(final TestPair pair) {
        assertThat(
            FingerprintUtils.getFingerprint(pair.getTest()),
            is(pair.getFingerprint()));
    }
}

