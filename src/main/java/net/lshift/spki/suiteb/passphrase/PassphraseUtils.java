package net.lshift.spki.suiteb.passphrase;

import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHA384Digest;

import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.Ec;

public class PassphraseUtils {
    private static final int SALT_LENGTH = 8;
    private static final int DEFAULT_ITERATIONS = 16;

    public static KeyFromPassphrase generate(
        String passphraseId,
        String passphrase) {
        return generate(DEFAULT_ITERATIONS, passphraseId, passphrase);
    }

    public static KeyFromPassphrase generate(
        int iterations,
        String passphraseId,
        String passphrase) {
        byte [] salt = Ec.randomBytes(SALT_LENGTH);
        AesKey key = getKey(passphraseId, salt, iterations, passphrase);
        return new KeyFromPassphrase(
            new PassphraseProtectedKey(passphraseId, salt, iterations, key.getKeyId()),
            key);
    }

    public static AesKey getKey(
        String passphraseId,
        byte[] salt,
        int iterations,
        String passphrase) {
        KeyStart keyStart = new KeyStart(passphraseId, salt, iterations, passphrase);
        DigestSha384 initialDigest = DigestSha384.digest(KeyStart.class, keyStart);
        byte[] digest = initialDigest.getBytes().clone();
        for (int i = 0; i < 1<<iterations; i++) {
            final SHA384Digest sha = new SHA384Digest();
            sha.update(digest, 0, digest.length);
            sha.doFinal(digest, 0);
        }
        return new AesKey(Arrays.copyOf(digest, AesKey.AES_KEY_BYTES));
    }
}
