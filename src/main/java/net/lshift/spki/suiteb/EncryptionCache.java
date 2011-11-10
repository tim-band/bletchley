package net.lshift.spki.suiteb;

import java.util.HashMap;
import java.util.Map;

/**
 * Cache PK encryption operations for a given PK.
 */
public class EncryptionCache {
    private final Map<DigestSha384, EncryptionSetup> cache = new HashMap<DigestSha384, EncryptionSetup>();

    public synchronized EncryptionSetup setupEncrypt(
        final PublicEncryptionKey publicKey) {
        EncryptionSetup res = cache.get(publicKey.getKeyId());
        if (res == null) {
            res = publicKey.setupEncrypt();
            cache.put(publicKey.getKeyId(), res);
        }
        return res;
    }

}
