package net.lshift.spki.suiteb;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.Constants;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.junit.Test;

public class MultipleRecipientEncryptionTest
{
    @Test
    public void test() throws IOException
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
            "The magic words are squeamish ossifrage".getBytes(Constants.ASCII));
        List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        AesKey aesKey = AesKey.generateAESKey();
        System.out.println("Master key:");
        ConvertUtils.prettyPrint(AesKey.class, aesKey, System.out);
        ConvertUtils.prettyPrint(AesKeyId.class, aesKey.getKeyId(), System.out);
        for (PublicEncryptionKey pKey : publicKeys) {
            AesKey rKey = pKey.setupEncrypt(sequenceItems);
            System.out.println("Subkey:");
            ConvertUtils.prettyPrint(AesKey.class, rKey, System.out);
            ConvertUtils.prettyPrint(AesKeyId.class, rKey.getKeyId(), System.out);
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


}
