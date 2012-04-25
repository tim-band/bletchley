package net.lshift.spki.suiteb.fingerprint;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import net.lshift.spki.convert.Writeable;
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

    public static final List<String> WORDLIST = getWordlist();
    public static final int NUM_WORDS = WORDLIST.size();

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
            throw new RuntimeException(e);
        }
    }

    public static <T extends Writeable> String getFingerprint(final Class<T> clazz, final T o) {
        return getFingerprint(DigestSha384.digest(clazz, o));
    }

    public static String getFingerprint(final DigestSha384 digest) {
        final DigestRng rng = new DigestRng(digest);
        final StringBuffer res = new StringBuffer();
        res.append(rng.nextChoice(WORDLIST));
        for (final char s: SEPARATORS.toCharArray()) {
            res.append(s);
            res.append(rng.nextChoice(WORDLIST));
        }
        return res.toString();
    }
}
