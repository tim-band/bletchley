package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.SequenceUtils.sequenceOrItem;

import java.util.HashMap;
import java.util.Map;


/**
 * Cache PK encryption operations for a given PK.
 */
public class EncryptionCache {
    private final PrivateEncryptionKey privateKey;
    private final Map<DigestSha384, AesKey> cache = new HashMap<>();

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
        return new EcdhItem(
            privateKey.getPublicKey().getKeyId(), recipient.getKeyId());
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
        final SequenceItem... messages) {
        return sequence(
            ecdhItem(recipient),
            getKeyAsSender(recipient).encrypt(sequenceOrItem(messages)));
    }

    public static EncryptionCache ephemeralKey() {
        return new EncryptionCache(PrivateEncryptionKey.generate());
    }
}
