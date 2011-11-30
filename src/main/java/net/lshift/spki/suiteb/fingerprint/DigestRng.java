package net.lshift.spki.suiteb.fingerprint;

import java.util.List;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.DigestSha384;

/**
 * A deterministic "random" number generator seeded on a digest.
 */
public class DigestRng {
    private final byte[] initialBytes;
    private byte[] randomBytes;
    private int useCounter = 0;
    private int byteOff;
    private int x = 0;
    private int xlim = 1;

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

    public DigestRng(DigestSha384 digest) {
        initialBytes = digest.getBytes();
        prepareBytes();
    }

    private void prepareBytes() {
        DigestSha384 digest = DigestSha384.digest(NextBytes.class,
            new NextBytes(useCounter, initialBytes));
        randomBytes = digest.getBytes();
        useCounter++;
        byteOff = 0;
    }

    private int getByte() {
        if (byteOff >= randomBytes.length) {
            prepareBytes();
            byteOff = 0;
        }
        return 0xff & randomBytes[byteOff++];
    }

    public int random(int size) {
        while (true) {
            int k = xlim / size;
            if (k == 0) {
                x *= 256; x += getByte(); xlim *= 256;
            } else if (x < k * size) {
                int res = x % size;
                x /= size; xlim = k;
                return res;
            } else {
                x -= k * size; xlim -= k * size;
            }
        }
    }

    public <T> T randomPick(List<T> list) {
        return list.get(random(list.size()));
    }
}
