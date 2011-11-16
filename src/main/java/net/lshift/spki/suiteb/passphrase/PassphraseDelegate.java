package net.lshift.spki.suiteb.passphrase;

import net.lshift.spki.suiteb.AesKey;

public interface PassphraseDelegate {

    public AesKey getPassphrase(PassphraseProtectedKey ppk);

}
