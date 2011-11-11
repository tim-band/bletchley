package net.lshift.spki.suiteb.fingerprint;

import java.io.IOException;
import java.util.List;

import net.lshift.spki.suiteb.DigestSha384;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;

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
        return getFingerprint(digest.getBytes());
    }

    private static String getFingerprint(byte[] bs) {
        byte[] bytes = bs;
        StringBuffer res = new StringBuffer();
        int i = 0;
        int x = 0;
        int xlim = 1;
        // Invariant: x is a random number 0 <= x < xlim
        while (true) {
            for (byte b: bytes) {
                x *= 256; x += (b & 0xff); xlim *= 256;
                if (xlim >= NUM_WORDS) {
                    int k = xlim / NUM_WORDS;
                    if (x < k * NUM_WORDS) {
                        res.append(WORDLIST.get(x % NUM_WORDS));
                        if (i == SEPARATORS.length()) {
                            return res.toString();
                        }
                        res.append(SEPARATORS.charAt(i));
                        i ++;
                        x /= NUM_WORDS; xlim = k;
                    } else {
                        x -= k * NUM_WORDS; xlim -= k * NUM_WORDS;
                    }
                }
            }
            Digest digest = new SHA384Digest();
            digest.update(bytes, 0, bytes.length);
            if (bytes == bs)
                bytes = new byte[bs.length];
            digest.doFinal(bytes, 0);
        }
    }
}
