package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.InvalidCipherTextException;

import net.lshift.spki.ParseException;
import net.lshift.spki.suiteb.sexpstructs.ECDHItem;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

public class InferenceEngine
{
    private Map<DigestSha384, PrivateEncryptionKey> dhKeys
        = new HashMap<DigestSha384, PrivateEncryptionKey>();
    private Map<AESKeyId, AESKey> aesKeys = new HashMap<AESKeyId, AESKey>();
    private ArrayList<SimpleMessage> messages = new ArrayList<SimpleMessage>();

    // FIXME: use dynamic dispatch here
    public void process(SequenceItem item)
    {
        if (item instanceof Sequence) {
            process((Sequence) item);
        } else if (item instanceof ECDHItem) {
            process((ECDHItem) item);
        } else if (item instanceof AESPacket) {
            process((AESPacket) item);
        } else if (item instanceof SimpleMessage) {
            process((SimpleMessage) item);
        }
    }

    public void process(PrivateEncryptionKey privateKey)
    {
        dhKeys.put(privateKey.getPublicKey().getKeyId(), privateKey);
    }

    public void process(Sequence items)
    {
        for (SequenceItem item: items.sequence) {
            process(item);
        }
    }

    public void process(ECDHItem item)
    {
        PrivateEncryptionKey key = dhKeys.get(item.recipient);
        process(new AESKey(item.keyId, key.getKey(item.ephemeralKey)));
    }

    public void process(AESKey key)
    {
        aesKeys.put(key.keyId, key);
    }

    public void process(SimpleMessage message) {
        messages.add(message);
    }

    public void process(AESPacket packet)
    {
        try {
            AESKey key = aesKeys.get(packet.keyId);
            process(key.decrypt(packet));
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public List<SimpleMessage> getMessages()
    {
        return messages;
    }
}
