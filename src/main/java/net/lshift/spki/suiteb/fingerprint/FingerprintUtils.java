package net.lshift.spki.suiteb.fingerprint;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.suiteb.DigestSha384;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;

public class FingerprintUtils {
    public static final int GROUP_LENGTH = 5;
    public static final String SEPARATORS = "--/--/--/--/--";
    public static final int NUM_GROUPS = SEPARATORS.length()+1;
    public static final int NUM_CHARS = GROUP_LENGTH * NUM_GROUPS;

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

    public static <T> String getFingerprint(
        Class<T> clazz,
        T o) {
        return getFingerprint(DigestSha384.digest(clazz, o));
    }

    public static String getFingerprint(DigestSha384 digest) {
        List<String> groups = getFingerprintGroups(digest.getBytes());
        StringBuffer res = new StringBuffer(NUM_CHARS + NUM_GROUPS -1);
        for (int i = 0; i < NUM_GROUPS; i++) {
            if (i > 0) {
                res.append(SEPARATORS.charAt(i-1));
            }
            res.append(groups.get(i));
        }
        return res.toString();
    }

    private static List<String> getFingerprintGroups(byte[] bs) {
        byte[] bytes = bs;
        List<String> res = new ArrayList<String>();
        int x = 0;
        int xlim = 1;
        while (true) {
            for (byte b: bytes) {
                x *= 256;
                xlim *= 256;
                x += (b & 0xff);
                if (xlim >= NUM_WORDS) {
                    int k = xlim / NUM_WORDS;
                    if (x < k * NUM_WORDS) {
                        res.add(WORDLIST.get(x % NUM_WORDS));
                        if (res.size() == NUM_GROUPS) {
                            return res;
                        }
                        x /= NUM_WORDS;
                        xlim = k;
                    } else {
                        x -= k * NUM_WORDS;
                        xlim -= k * NUM_WORDS;
                    }
                }
            }
            redigest(bytes);
        }
    }

    private static void redigest(byte[] bytes) {
        Digest digest = new SHA384Digest();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(bytes, 0);
    }
}
