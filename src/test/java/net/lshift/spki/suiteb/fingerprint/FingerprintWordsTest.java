package net.lshift.spki.suiteb.fingerprint;

import static net.lshift.spki.suiteb.fingerprint.FingerprintUtils.WORDLIST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.regex.Pattern;

import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class FingerprintWordsTest {
    private static final Pattern WORDREX
        = Pattern.compile("[a-z]{1,6}");

    private static boolean isValidWord(final String word) {
        return WORDREX.matcher(word).matches();
    }

    @Test
    public void testBadWordsAreRejected() {
        final String[] badwords = new String [] {
                        "", " ", " x", "x ", "X", "\u00e9", "it's"};
        for (final String word: badwords)
            assertFalse(isValidWord(word));
    }

    @DataPoints
    public static String[] words() {
        return WORDLIST.toArray(new String[WORDLIST.size()]);
    }

    @Theory
    public void theoryWordsAreValid(final String word) {
        assertTrue(isValidWord(word));
    }

    @Test
    public void testWordsAreUnique() {
        final HashSet<String> wordSet = new HashSet<String>(WORDLIST);
        assertEquals(WORDLIST.size(), wordSet.size());
    }

    @Test
    public void testEntropyIsHighEnough() {
        assertTrue((Math.log(WORDLIST.size())/Math.log(2)
            * FingerprintUtils.NUM_GROUPS) > 192);
    }
}
