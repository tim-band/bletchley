package net.lshift.spki.suiteb;

import net.lshift.spki.suiteb.sexpstructs.EcdhItem;

public class EncryptionSetup {
    public final EcdhItem encryptedKey;
    public final AesKey key;

    public EncryptionSetup(final EcdhItem encryptedKey, final AesKey key) {
        super();
        this.encryptedKey = encryptedKey;
        this.key = key;
    }
}
