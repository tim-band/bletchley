package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

/**
 * Encrypt/decrypt messages intended for multiple recipients.
 */
public class MultipleRecipient
{
    public static void encrypt(
        List<SequenceItem> sequenceItems,
        List<PublicEncryptionKey> publicKeys,
        SequenceItem message)
    {
        AESKey aesKey = EC.generateAESKey();
        for (PublicEncryptionKey pKey : publicKeys) {
            AESKey rKey = pKey.setupEncrypt(sequenceItems);
            sequenceItems.add(rKey.encrypt(aesKey));
        }
        sequenceItems.add(aesKey.encrypt(message));
    }

    public static SequenceItem encrypt(
        List<PublicEncryptionKey> publicKeys,
        SequenceItem message)
    {
        List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        encrypt(sequenceItems, publicKeys, message);
        return new Sequence(sequenceItems);
    }

    // FIXME: this can only decrypt SimpleMessagse
    public static SimpleMessage decrypt(
        PrivateEncryptionKey k,
        SequenceItem packet)
    {
        InferenceEngine inferenceEngine = new InferenceEngine();
        inferenceEngine.process(k);
        inferenceEngine.process(packet);
        List<SimpleMessage> messages = inferenceEngine.getMessages();
        assert messages.size() == 1;
        return messages.get(0);
    }
}
