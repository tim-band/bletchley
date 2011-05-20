package net.lshift.spki.suiteb;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.Constants;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceConversion;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.junit.Test;

public class MultipleRecipientEncryptionTest
{
    @Test
    public void test()
    {
        List<PrivateEncryptionKey> keys = new ArrayList<PrivateEncryptionKey>();
        List<PublicEncryptionKey> publicKeys = new ArrayList<PublicEncryptionKey>();
        for (int i = 0; i < 3; i++) {
            PrivateEncryptionKey k = PrivateEncryptionKey.generate();
            keys.add(k);
            publicKeys.add(k.getPublicKey());
        }
        SimpleMessage message = new SimpleMessage(
            MultipleRecipientEncryptionTest.class.getCanonicalName(),
            "The magic words are squeamish ossifrage".getBytes(Constants.UTF8));
        List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        AesKey aesKey = AesKey.generateAESKey();
        for (PublicEncryptionKey pKey : publicKeys) {
            AesKey rKey = pKey.setupEncrypt(sequenceItems);
            sequenceItems.add(rKey.encrypt(aesKey));
        }
        sequenceItems.add(aesKey.encrypt(message));
        SequenceItem packet
            = new Sequence(sequenceItems);
        packet = RoundTrip.roundTrip(
            SequenceItem.class, packet);
        for (PrivateEncryptionKey k: keys) {
            InferenceEngine inferenceEngine = new InferenceEngine();
            inferenceEngine.process(k);
            inferenceEngine.process(packet);
            List<SimpleMessage> messages = inferenceEngine.getMessages();
            assertEquals(1, messages.size());
            SimpleMessage result = messages.get(0);
            assertEquals(message, result);
        }
    }

    static {
        SequenceConversion.ensureInstalled();
    }
}
