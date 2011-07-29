package net.lshift.spki.suiteb;

import net.lshift.spki.suiteb.sexpstructs.EcdhItem;

/**
 * Details needed to send an encrypted message: a secret key, and an
 * EcdhItem that encodes it for a given public key.
 */
public class EncryptionSetup {
    public final EcdhItem encryptedKey;
    public final AesKey key;

    public EncryptionSetup(final EcdhItem encryptedKey, final AesKey key) {
        super();
        this.encryptedKey = encryptedKey;
        this.key = key;
    }
}
