package net.lshift.spki.suiteb.passphrase;

import net.lshift.spki.suiteb.AesKey;

public class KeyFromPassphrase {
    private final PassphraseProtectedKey passphraseProtectedKey;
    private final AesKey aesKey;

    public KeyFromPassphrase(final PassphraseProtectedKey passphraseProtectedKey,
                             final AesKey aesKey) {
        this.passphraseProtectedKey = passphraseProtectedKey;
        this.aesKey = aesKey;
    }

    public PassphraseProtectedKey getPassphraseProtectedKey() {
        return passphraseProtectedKey;
    }

    public AesKey getAesKey() {
        return aesKey;
    }
}
