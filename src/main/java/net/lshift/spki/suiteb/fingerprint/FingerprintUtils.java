package net.lshift.spki.suiteb.fingerprint;

import net.lshift.spki.suiteb.DigestSha384;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;

public class FingerprintUtils {
    private static final int STRETCH_ROUNDS = 1<<8;
    public static final int GROUP_LENGTH = 5;
    public static final String SEPARATORS = "--/--/--";
    public static final int NUM_GROUPS = SEPARATORS.length()+1;
    public static final int NUM_CHARS = GROUP_LENGTH * NUM_GROUPS;

    public static <T> String getFingerprint(
        Class<T> clazz,
        T o) {
        return getFingerprint(DigestSha384.digest(clazz, o));
    }

    public static String getFingerprint(DigestSha384 digest) {
        String ungrouped = getUngroupedFingerprint(digest.getBytes());
        StringBuffer res = new StringBuffer(NUM_CHARS + NUM_GROUPS -1);
        for (int i = 0; i < NUM_GROUPS; i++) {
            if (i > 0) {
                res.append(SEPARATORS.charAt(i-1));
            }
            res.append(ungrouped.substring(i*GROUP_LENGTH, (i+1)*GROUP_LENGTH));
        }
        return res.toString();
    }

    private static String getUngroupedFingerprint(byte[] bs) {
        byte[] bytes = bs;
        for (int i = 0; i < STRETCH_ROUNDS; i++) {
            redigest(bytes);
        }
        StringBuffer res = new StringBuffer(NUM_CHARS);
        while (true) {
            for (byte b: bytes) {
                int ival = b & 0xff;
                if (ival < 26*9) {
                    res.append((char)('a' +(ival % 26)));
                    if (res.length() == NUM_CHARS) {
                        return res.toString();
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
