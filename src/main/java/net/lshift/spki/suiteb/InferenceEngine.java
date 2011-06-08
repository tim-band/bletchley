package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.ParseException;
import net.lshift.spki.suiteb.sexpstructs.EcdhItem;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.bouncycastle.crypto.InvalidCipherTextException;

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
    private Map<DigestSha384, DigestSha384> signedBy
        = new HashMap<DigestSha384, DigestSha384>();
    private Map<DigestSha384, List<SequenceItem>> hasSigned
        = new HashMap<DigestSha384, List<SequenceItem>>();
    // FIXME: this should go altogether - we should provide no way
    // of accessing unsigned content
    private List<SimpleMessage> messages
        = new ArrayList<SimpleMessage>();

    public void process(SequenceItem item) {
        process(item, null);
    }

    // FIXME: use dynamic dispatch here
    public void process(SequenceItem item, DigestSha384 contextSigner) {
        DigestSha384 signer = contextSigner;
        if (signer == null) {
            DigestSha384 digest = DigestSha384.digest(item);
            signer = signedBy.get(digest);
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
            throw new RuntimeException(
                "Don't know how to process sequence item: "
                + item.getClass().getCanonicalName());
        }
    }

    public void process(PrivateEncryptionKey privateKey) {
        dhKeys.put(privateKey.getPublicKey().getKeyId(), privateKey);
    }

    public void process(Sequence items, DigestSha384 signer) {
        for (SequenceItem item: items.sequence) {
            process(item, signer);
        }
    }

    public void process(EcdhItem item) {
        PrivateEncryptionKey key = dhKeys.get(item.recipient);
        if (key != null) {
            process(new AesKey(key.getKey(item.ephemeralKey)));
        }
    }

    public void process(AesKey key) {
//        try {
//            System.out.println("Processing key:");
//            ConvertUtils.prettyPrint(AesKey.class, key, System.out);
//            System.out.println("ID:");
//            ConvertUtils.prettyPrint(AesKeyId.class, key.getKeyId(), System.out);
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
        aesKeys.put(key.getKeyId(), key);
    }

    public void process(PublicSigningKey pKey) {
        dsaKeys.put(pKey.getKeyId(), pKey);
    }

    public void process(Signature sig) {
        PublicSigningKey pKey = dsaKeys.get(sig.keyId);
        if (pKey == null) return;
        if (!pKey.validate(sig.digest, sig.rawSignature))
            throw new RuntimeException("Sig validation failure");
        // FIXME: assert that it's not already signed?
        signedBy.put(sig.digest, sig.keyId);
    }

    public void process(SimpleMessage message, DigestSha384 signer) {
        messages.add(message);
        if (signer != null) {
            listPut(hasSigned, signer, message);
        }
    }

    public void process(AesPacket packet) {
        try {
//            try {
//                System.out.println("Packet encrypted with:");
//                ConvertUtils.prettyPrint(AesKeyId.class, packet.keyId, System.out);
//            } catch (IOException e) {
//                throw new RuntimeException(e);
//            }
            AesKey key = aesKeys.get(packet.keyId);
            if (key != null) {
                final SequenceItem contents = key.decrypt(packet);
//                try {
//                    System.out.println("Contents:");
//                    ConvertUtils.prettyPrint(SequenceItem.class, contents, System.out);
//                } catch (IOException e) {
//                    throw new RuntimeException(e);
//                }
                process(contents);
            }
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public void process(DigestSha384 digest, DigestSha384 signer) {
        if (signer != null) {
            signedBy.put(digest, signer);
        }
    }

    public List<SimpleMessage> getMessages() {
        return messages;
    }

    public List<SequenceItem> getSignedBy(DigestSha384 keyId) {
        return hasSigned.get(keyId);
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
