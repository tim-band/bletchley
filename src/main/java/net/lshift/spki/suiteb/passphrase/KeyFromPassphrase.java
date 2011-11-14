package net.lshift.spki.suiteb.passphrase;

import net.lshift.spki.suiteb.AesKey;

public class KeyFromPassphrase {
    private final PassphraseProtectedKey passphraseProtectedKey;
    private final AesKey aesKey;

    public KeyFromPassphrase(PassphraseProtectedKey passphraseProtectedKey,
                             AesKey aesKey) {
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
