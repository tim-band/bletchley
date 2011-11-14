package net.lshift.spki.suiteb.fingerprint;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.regex.Pattern;

import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class FingerprintWordsTest {
    private static final Pattern WORDREX
        = Pattern.compile("[a-z]+");

    private boolean isValidWord(String word) {
        return WORDREX.matcher(word).matches();
    }

    @Test
    public void testBadWordsAreRejected() {
        final String[] badwords = new String [] {
                        "", " ", " x", "x ", "X", "\u00e9", "it's"};
        for (String word: badwords)
            assertFalse(isValidWord(word));
    }

    @DataPoints
    public static String[] words() {
        return FingerprintUtils.WORDLIST.toArray(new String[0]);
    }

    @Theory
    public void theoryWordsAreValid(String word) {
        assertTrue(isValidWord(word));
    }

    @Test
    public void testEntropyIsHighEnough() {
        assertTrue((Math.log(FingerprintUtils.WORDLIST.size())/Math.log(2)
            * FingerprintUtils.NUM_GROUPS) > 192);
    }
}
