package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.SequenceUtils.sequenceOrItem;

import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.suiteb.sexpstructs.EcdhItem;

/**
 * Cache PK encryption operations for a given PK.
 */
public class EncryptionCache {
    private final PrivateEncryptionKey privateKey;
    private final Map<DigestSha384, AesKey> cache = new HashMap<DigestSha384, AesKey>();

    public EncryptionCache(final PrivateEncryptionKey privateKey) {
        this.privateKey = privateKey;
    }

    public PrivateEncryptionKey getPrivateKey() {
        return privateKey;
    }

    public PublicEncryptionKey getPublicKey() {
        return privateKey.getPublicKey();
    }

    // Convenience method
    public EcdhItem ecdhItem(final PublicEncryptionKey recipient) {
        return EcdhItem.ecdhItem(privateKey, recipient);
    }

    public synchronized AesKey getKeyAsSender(
        final PublicEncryptionKey publicKey) {
        AesKey res = cache.get(publicKey.getKeyId());
        if (res == null) {
            res = privateKey.getKeyAsSender(publicKey);
            cache.put(publicKey.getKeyId(), res);
        }
        return res;
    }

    public synchronized Sequence encrypt(
        final PublicEncryptionKey recipient,
        SequenceItem... messages) {
        return sequence(getPublicKey(),
            ecdhItem(recipient),
            getKeyAsSender(recipient).encrypt(sequenceOrItem(messages)));
    }
}
