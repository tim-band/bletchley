package net.lshift.spki.suiteb.passphrase;

import java.io.Console;
import java.util.Arrays;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.Ec;

import org.bouncycastle.crypto.digests.SHA384Digest;

public class PassphraseUtils {
    private static final int SALT_LENGTH = 8;
    private static final int DEFAULT_ITERATIONS = 16;

    public static KeyFromPassphrase generate(
        final String passphraseId,
        final String passphrase) {
        return generate(DEFAULT_ITERATIONS, passphraseId, passphrase);
    }

    public static KeyFromPassphrase generate(
        final int iterations,
        final String passphraseId,
        final String passphrase) {
        final byte [] salt = Ec.randomBytes(SALT_LENGTH);
        final AesKey key = getKey(passphraseId, salt, iterations, passphrase);
        return new KeyFromPassphrase(
            new PassphraseProtectedKey(passphraseId, salt, iterations, key.getKeyId()),
            key);
    }

    public static AesKey getKey(
        final String passphraseId,
        final byte[] salt,
        final int iterations,
        final String passphrase) {
        final KeyStart keyStart = new KeyStart(passphraseId, salt, iterations, passphrase);
        final DigestSha384 initialDigest = DigestSha384.digest(keyStart);
        final byte[] digest = initialDigest.getBytes().clone();
        for (int i = 0; i < 1<<iterations; i++) {
            final SHA384Digest sha = new SHA384Digest();
            sha.update(digest, 0, digest.length);
            sha.doFinal(digest, 0);
        }
        return new AesKey(Arrays.copyOf(digest, AesKey.AES_KEY_BYTES));
    }

    public static KeyFromPassphrase promptForNewPassphrase(final String passphraseId) {
        final Console console = System.console();
        if (console == null) {
            throw new RuntimeException("No console from which to read passphrase");
        }
        while (true) {
            final String passphrase = new String(console.readPassword(
                "New passphrase for \"%s\": ", passphraseId));
            if (passphrase.isEmpty()) {
                System.out.println("Passphrase is empty, trying again");
                continue;
            }
            final String confirm = new String(console.readPassword(
                    "Confirm new passphrase for \"%s\": ", passphraseId));
            if (!confirm.equals(passphrase)) {
                System.out.println("Passphrases do not match, trying again");
                continue;
            }
            return PassphraseUtils.generate(passphraseId, passphrase);
        }
    }

    public static AesKey promptForPassphrase(
        final PassphraseProtectedKey ppk) {
        final Console console = System.console();
        if (console == null) {
            throw new RuntimeException("No console from which to read passphrase");
        }
        while (true) {
            final String passphrase = new String(console.readPassword(
                "Passphrase for \"%s\": ", ppk.getPassphraseId()));
            try {
                return ppk.getKey(passphrase);
            } catch (final InvalidInputException e) {
                System.out.println("Wrong passphrase, trying again");
            }
        }
    }
}
