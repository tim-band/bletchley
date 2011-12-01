package net.lshift.spki.suiteb.fingerprint;

import java.util.List;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.DigestSha384;

/**
 * A deterministic "random" number generator seeded on a digest.
 */
public class DigestRng {
    private final byte[] initialBytes;
    private byte[] randomBytes = null;
    private int useCounter = 0;
    private int byteOff;
    private int x = 0;
    private int xlim = 1;

    public DigestRng(DigestSha384 digest) {
        initialBytes = digest.getBytes();
    }

    @Convert.ByPosition(name = "digest-rng", fields = { "counter", "digest" })
    private static class NextBytes {
        @SuppressWarnings("unused")
        private final Integer counter;
        @SuppressWarnings("unused")
        private final byte[] digest;

        public NextBytes(Integer counter, byte[] digest) {
            super();
            this.counter = counter;
            this.digest = digest;
        }
    }

    private int nextByte() {
        if (randomBytes == null || byteOff >= randomBytes.length) {
            DigestSha384 digest = DigestSha384.digest(NextBytes.class,
                new NextBytes(useCounter++, initialBytes));
            randomBytes = digest.getBytes();
            byteOff = 0;
        }
        return 0xff & randomBytes[byteOff++];
    }

    public int nextInt(int size) {
        while (true) {
            int k = xlim / size;
            if (k == 0) {
                x *= 256; x += nextByte(); xlim *= 256;
            } else if (x < k * size) {
                int res = x % size;
                x /= size; xlim = k;
                return res;
            } else {
                x -= k * size; xlim -= k * size;
            }
        }
    }

    public <T> T nextChoice(List<T> list) {
        return list.get(nextInt(list.size()));
    }
}
