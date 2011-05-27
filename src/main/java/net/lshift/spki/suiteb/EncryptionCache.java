package net.lshift.spki.suiteb;

import java.util.HashMap;
import java.util.Map;

public class EncryptionCache {
    private Map<DigestSha384, EncryptionSetup> cache = new HashMap<DigestSha384, EncryptionSetup>();

    public synchronized EncryptionSetup setupEncrypt(
        PublicEncryptionKey publicKey) {
        EncryptionSetup res = cache.get(publicKey.getKeyId());
        if (res == null) {
            res = publicKey.setupEncrypt();
            cache.put(publicKey.getKeyId(), res);
        }
        return res;
    }

}
