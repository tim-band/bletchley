package net.lshift.spki.suiteb.fingerprint;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

import net.lshift.spki.suiteb.DigestSha384;

import org.apache.commons.io.IOUtils;

/**
 * Generate a fingerprint from a digest using a word list.
 * The fingerprints are roughly fairly chosen from 2^192.5
 * possibilities.
 */
public class FingerprintUtils {
    public static final String SEPARATORS = "--/--/--/--/--";
    public static final int NUM_GROUPS = SEPARATORS.length()+1;

    public static final List<String> WORDLIST = Collections.unmodifiableList(getWordlist());
    public static final int NUM_WORDS = WORDLIST.size();

    private FingerprintUtils() { 
    	// Class cannot be instantiated
    }
    
    private static List<String> getWordlist() {
        try {
            final InputStream resourceStream
                = FingerprintUtils.class.getResourceAsStream("wordlist");
            try {
                return IOUtils.readLines(resourceStream);
            } finally {
                resourceStream.close();
            }
        } catch (final IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static String getFingerprint(final Object o) {
        return getFingerprint(DigestSha384.digest(o));
    }

    public static String getFingerprint(final DigestSha384 digest) {
        final DigestRng rng = new DigestRng(digest);
        final StringBuilder res = new StringBuilder();
        res.append(rng.nextChoice(WORDLIST));
        for (final char s: SEPARATORS.toCharArray()) {
            res.append(s);
            res.append(rng.nextChoice(WORDLIST));
        }
        return res.toString();
    }
}
