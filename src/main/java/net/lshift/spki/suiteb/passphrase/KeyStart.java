package net.lshift.spki.suiteb.passphrase;

import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name="digest-this-to-get-the-key",
fields={"passphraseId", "salt", "iterations", "passphrase"})
public class KeyStart {
    // This class is only used to create a digest, so
    // no getters are needed
    @SuppressWarnings("unused")
    private final String passphraseId;
    @SuppressWarnings("unused")
    private final byte [] salt;
    @SuppressWarnings("unused")
    private final Integer iterations;
    @SuppressWarnings("unused")
    private final String passphrase;

    public KeyStart(final String passphraseId, final byte[] salt, final int iterations,
                    final String passphrase) {
        this.passphraseId = passphraseId;
        this.salt = salt;
        this.iterations = iterations;
        this.passphrase = passphrase;
    }
}
