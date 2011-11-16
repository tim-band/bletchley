package net.lshift.spki.suiteb.passphrase;

import net.lshift.spki.suiteb.AesKey;

/**
 * The InferenceEngine consults one of these when it encounters a
 * PassphraseProtectedKey, to prompt the user for a passphrase in
 * an appropriate way.
 */
public interface PassphraseDelegate {

    public AesKey getPassphrase(PassphraseProtectedKey ppk);

}
