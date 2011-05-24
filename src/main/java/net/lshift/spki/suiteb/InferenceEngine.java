package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.InvalidCipherTextException;

import net.lshift.spki.ParseException;
import net.lshift.spki.suiteb.sexpstructs.EcdhItem;
import net.lshift.spki.suiteb.sexpstructs.EcdsaPublicKey;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

/**
 * Take a bunch of SequenceItems and figure out what you can infer from them.
 * Decrypt what you can decrypt, check the signatures you can check and so on.
 * ORDER MATTERS for the moment, but we could fix that if need be.
 * Full of limitations, but the principle is there, the limitations can be
 * fixed and it will do for now.
 */
public class InferenceEngine {
    private Map<DigestSha384, PrivateEncryptionKey> dhKeys
        = new HashMap<DigestSha384, PrivateEncryptionKey>();
    private Map<DigestSha384, PublicSigningKey> dsaKeys
        = new HashMap<DigestSha384, PublicSigningKey>();
    private Map<AesKeyId, AesKey> aesKeys = new HashMap<AesKeyId, AesKey>();
    // FIXME this is pretty ugly!
    private Map<DigestSha384, List<Signature>> signatures
        = new HashMap<DigestSha384, List<Signature>>();
    private Map<DigestSha384, List<SequenceItem>> signedBy
        = new HashMap<DigestSha384, List<SequenceItem>>();
    private Map<DigestSha384, SimpleMessage> messages
        = new HashMap<DigestSha384,SimpleMessage>();

    // FIXME: use dynamic dispatch here
    public void process(SequenceItem item) {
        DigestSha384 digest = DigestSha384.digest(SequenceItem.class, item);
        List<Signature> sigs = signatures.get(digest);
        if (sigs != null) {
            for (Signature sig: sigs) {
                listPut(signedBy, sig.keyId, item);
            }
        }
        if (item instanceof Sequence) {
            process((Sequence) item);
        } else if (item instanceof EcdhItem) {
            process((EcdhItem) item);
        } else if (item instanceof AesKey) {
            process((AesKey) item);
        } else if (item instanceof AesPacket) {
            process((AesPacket) item);
        } else if (item instanceof SimpleMessage) {
            process((SimpleMessage) item);
        } else if (item instanceof EcdsaPublicKey) {
            process((EcdsaPublicKey) item);
        } else if (item instanceof Signature) {
            process((Signature) item);
        } else {
            throw new RuntimeException(
                "Don't know how to process sequence item: "
                + item.getClass().getCanonicalName());
        }
    }

    public void process(PrivateEncryptionKey privateKey) {
        dhKeys.put(privateKey.getPublicKey().getKeyId(), privateKey);
    }

    public void process(Sequence items) {
        for (SequenceItem item: items.sequence) {
            process(item);
        }
    }

    public void process(EcdhItem item) {
        PrivateEncryptionKey key = dhKeys.get(item.recipient);
        if (key != null) {
            process(new AesKey(key.getKey(item.ephemeralKey)));
        }
    }

    public void process(AesKey key) {
        aesKeys.put(key.getKeyId(), key);
    }

    public void process(EcdsaPublicKey key) {
        process(PublicSigningKey.unpack(key));
    }

    public void process(PublicSigningKey pKey) {
        dsaKeys.put(pKey.getKeyId(), pKey);
    }

    public void process(Signature sig) {
        PublicSigningKey pKey = dsaKeys.get(sig.keyId);
        if (pKey == null) return;
        if (!pKey.validate(sig.digest, sig.rawSignature))
            throw new RuntimeException("Sig validation failure");
        listPut(signatures, sig.digest, sig);
    }

    public void process(SimpleMessage message) {
        messages.put(
            DigestSha384.digest(SimpleMessage.class, message), message);
    }

    public void process(AesPacket packet) {
        try {
            AesKey key = aesKeys.get(packet.keyId);
            if (key != null) {
                process(key.decrypt(packet));
            }
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public List<SimpleMessage> getMessages() {
        return new ArrayList<SimpleMessage>(messages.values());
    }

    public List<SequenceItem> getSignedBy(DigestSha384 keyId) {
        return signedBy.get(keyId);
    }

    private <K,V> void listPut(Map<K,List<V>> map,
        K key, V value)
    {
        List<V> list = map.get(key);
        if (list == null) {
            list = new ArrayList<V>();
            map.put(key, list);
        }
        list.add(value);
    }
}
