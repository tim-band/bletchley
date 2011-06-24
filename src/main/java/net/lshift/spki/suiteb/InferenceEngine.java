package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.sexpstructs.EcdhItem;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Take a bunch of SequenceItems and figure out what you can infer from them.
 * Decrypt what you can decrypt, check the signatures you can check and so on.
 * ORDER MATTERS for the moment, but we could fix that if need be.
 * Full of limitations, but the principle is there, the limitations can be
 * fixed and it will do for now.
 */
public class InferenceEngine {
    private static final Logger LOG
        = LoggerFactory.getLogger(InferenceEngine.class);

    private final Map<DigestSha384, PrivateEncryptionKey> dhKeys
        = new HashMap<DigestSha384, PrivateEncryptionKey>();
    private final Map<DigestSha384, PublicSigningKey> dsaKeys
        = new HashMap<DigestSha384, PublicSigningKey>();
    private final Map<AesKeyId, AesKey> aesKeys = new HashMap<AesKeyId, AesKey>();
    // FIXME this is pretty ugly!
    private final Map<DigestSha384, DigestSha384> signedBy
        = new HashMap<DigestSha384, DigestSha384>();
    private final Map<DigestSha384, List<SequenceItem>> hasSigned
        = new HashMap<DigestSha384, List<SequenceItem>>();
    // FIXME: this should go altogether - we should provide no way
    // of accessing unsigned content
    private final List<SimpleMessage> messages
        = new ArrayList<SimpleMessage>();

    private final Map<String, String> byteNames = new HashMap<String,String>();

    private String bytesString(final byte[] bytes) {
        final String string = "|" + Base64.encodeBase64String(bytes) + "|";
        String name = byteNames.get(string);
        if (name == null) {
            name = Integer.toString(byteNames.size(), 36);
            byteNames.put(string, name);
        }
        return "\"" + name + "\"-" + string;
    }

    private String digestString(DigestSha384 digest) {
        return bytesString(digest.getBytes());
    }

    public void process(final SequenceItem item) throws InvalidInputException {
        process(item, null);
    }

    // FIXME: use dynamic dispatch here
    public void process(final SequenceItem item, final DigestSha384 contextSigner) throws InvalidInputException {
        DigestSha384 signer = contextSigner;
        if (signer == null) {
            final DigestSha384 digest = DigestSha384.digest(item);
            signer = signedBy.get(digest);
            if (signer != null && LOG.isDebugEnabled()) {
                LOG.debug("Signed object found, signer {} signed {}",
                    digestString(signer), digestString(digest));
                LOG.debug(
                    ConvertUtils.prettyPrint(SequenceItem.class, item));
            }
        }
        if (item instanceof Sequence) {
            process((Sequence) item, signer);
        } else if (item instanceof EcdhItem) {
            process((EcdhItem) item);
        } else if (item instanceof AesKey) {
            process((AesKey) item);
        } else if (item instanceof AesPacket) {
            // Propagate signer?
            process((AesPacket) item);
        } else if (item instanceof SimpleMessage) {
            process((SimpleMessage) item, signer);
        } else if (item instanceof PublicSigningKey) {
            process((PublicSigningKey) item);
        } else if (item instanceof Signature) {
            process((Signature) item);
        } else if (item instanceof DigestSha384) {
            process((DigestSha384) item, signer);
        } else {
            throw new InvalidInputException(
                "Don't know how to process sequence item: "
                + item.getClass().getCanonicalName());
        }
    }

    public void process(final PrivateEncryptionKey privateKey) {
        final DigestSha384 keyId = privateKey.getPublicKey().getKeyId();
        LOG.debug("Adding private encryption key: {}", digestString(keyId));
        dhKeys.put(keyId, privateKey);
    }

    public void process(final Sequence items, final DigestSha384 signer)
        throws InvalidInputException {
        LOG.debug("Processing sequence...");
        for (final SequenceItem item: items.sequence) {
            process(item, signer);
        }
        LOG.debug("...sequence processed.");
    }

    public void process(final EcdhItem item) {
        final PrivateEncryptionKey key = dhKeys.get(item.recipient);
        if (key == null) {
            LOG.debug("Skipping encrypted packet for recipient {}",
                digestString(item.recipient));
        } else {
            LOG.debug("Processing encrypted packet for recipient {}",
                digestString(item.recipient));
            process(new AesKey(key.getKey(item.ephemeralKey)));
        }
    }

    public void process(final AesKey key) {
        LOG.debug("Adding AES key id {}",
            bytesString(key.getKeyId().keyId));
        aesKeys.put(key.getKeyId(), key);
    }

    public void process(final PublicSigningKey pKey) {
        final DigestSha384 keyId = pKey.getKeyId();
        LOG.debug("Adding public signing key: {}", digestString(keyId));
        dsaKeys.put(keyId, pKey);
    }

    public void process(final Signature sig) throws InvalidInputException {
        final PublicSigningKey pKey = dsaKeys.get(sig.keyId);
        if (pKey == null) {
            LOG.debug("Skipping signature from unknown signer {} for {}",
                digestString(sig.keyId), digestString(sig.digest));
            return;
        }
        if (!pKey.validate(sig.digest, sig.rawSignature))
            throw new InvalidInputException("Sig validation failure");
        LOG.debug("Signer {} attests to {}",
            digestString(sig.keyId), digestString(sig.digest));
        // FIXME: assert that it's not already signed?
        signedBy.put(sig.digest, sig.keyId);
    }

    public void process(final SimpleMessage message, final DigestSha384 signer) {
        messages.add(message);
        if (signer != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found message signed by {}:\n{}",
                    digestString(signer),
                    ConvertUtils.prettyPrint(SimpleMessage.class, message));
            }
            listPut(hasSigned, signer, message);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Message has no known signer:\n{}",
                    ConvertUtils.prettyPrint(SimpleMessage.class, message));
            }
        }
    }

    public void process(final AesPacket packet) throws InvalidInputException {
        final AesKey key = aesKeys.get(packet.keyId);
        if (key != null) {
            final SequenceItem contents = key.decrypt(packet);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Decrypted packet with key {}:\n{}",
                    bytesString(packet.keyId.keyId),
                    ConvertUtils.prettyPrint(SequenceItem.class, contents));
            }
            process(contents);
        } else {
            LOG.debug("Skipping packet encrypted with unknown key {}",
                bytesString(packet.keyId.keyId));
        }
    }

    public void process(final DigestSha384 digest, final DigestSha384 signer) {
        if (signer != null) {
            LOG.debug("Chained signature from {} for {}",
                digestString(signer), digestString(digest));
            signedBy.put(digest, signer);
        }
    }

    public List<SimpleMessage> getMessages() {
        return messages;
    }

    public List<SequenceItem> getSignedBy(final DigestSha384 keyId) {
        final List<SequenceItem> res = hasSigned.get(keyId);
        if (res != null) {
            return res;
        }
        return Collections.emptyList();
    }

    private <K,V> void listPut(final Map<K,List<V>> map,
        final K key, final V value)
    {
        List<V> list = map.get(key);
        if (list == null) {
            list = new ArrayList<V>();
            map.put(key, list);
        }
        list.add(value);
    }
}
