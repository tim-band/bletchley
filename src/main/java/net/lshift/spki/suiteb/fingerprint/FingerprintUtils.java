package net.lshift.spki.suiteb.fingerprint;

import java.io.IOException;
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

    public static final List<String> WORDLIST;
    static {
        try {
            WORDLIST = IOUtils.readLines(
                FingerprintUtils.class.getResourceAsStream("wordlist"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static final int NUM_WORDS = WORDLIST.size();

    public static <T> String getFingerprint(Class<T> clazz, T o) {
        return getFingerprint(DigestSha384.digest(clazz, o));
    }

    public static String getFingerprint(DigestSha384 digest) {
        DigestRng rng = new DigestRng(digest);
        StringBuffer res = new StringBuffer();
        res.append(rng.randomPick(WORDLIST));
        for (char s: SEPARATORS.toCharArray()) {
            res.append(s);
            res.append(rng.randomPick(WORDLIST));
        }
        return res.toString();
    }
}
