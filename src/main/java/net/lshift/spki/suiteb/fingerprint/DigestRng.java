package net.lshift.spki.suiteb.fingerprint;

import java.util.List;

import com.google.protobuf.ByteString;

import net.lshift.bletchley.suiteb.proto.DigestRngProto;
import net.lshift.bletchley.suiteb.proto.DigestRngProto.NextBytes.Builder;
import net.lshift.spki.convert.ProtobufConvert;
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

    public DigestRng(final DigestSha384 digest) {
        initialBytes = digest.getBytes();
    }

    private static class NextBytes 
    implements ProtobufConvert<DigestRngProto.NextBytes.Builder> {
        private final Integer counter;
        private final byte[] digest;

        public NextBytes(final Integer counter, final byte[] digest) {
            this.counter = counter;
            this.digest = digest;
        }

        @Override
        public Builder toProtobuf() {
            return DigestRngProto.NextBytes.newBuilder()
                    .setCounter(counter)
                    .setDigest(ByteString.copyFrom(digest));
        }
    }

    private int nextByte() {
        if (randomBytes == null || byteOff >= randomBytes.length) {
            randomBytes = DigestSha384.digest(
                new NextBytes(useCounter++, initialBytes));
            byteOff = 0;
        }
        return 0xff & randomBytes[byteOff++];
    }

    public int nextInt(final int size) {
        while (true) {
            final int k = xlim / size;
            if (k == 0) {
                x *= 256; x += nextByte(); xlim *= 256;
            } else if (x < k * size) {
                final int res = x % size;
                x /= size; xlim = k;
                return res;
            } else {
                x -= k * size; xlim -= k * size;
            }
        }
    }

    public <T> T nextChoice(final List<T> list) {
        return list.get(nextInt(list.size()));
    }
}
