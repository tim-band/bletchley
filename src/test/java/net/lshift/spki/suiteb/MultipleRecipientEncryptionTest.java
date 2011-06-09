package net.lshift.spki.suiteb;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.Constants;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.junit.Test;

public class MultipleRecipientEncryptionTest
{
    @Test
    public void test() throws IOException, InvalidInputException
    {
        final List<PrivateEncryptionKey> keys = new ArrayList<PrivateEncryptionKey>();
        final List<PublicEncryptionKey> publicKeys = new ArrayList<PublicEncryptionKey>();
        for (int i = 0; i < 3; i++) {
            final PrivateEncryptionKey k = PrivateEncryptionKey.generate();
            keys.add(k);
            publicKeys.add(k.getPublicKey());
        }
        final SimpleMessage message = new SimpleMessage(
            MultipleRecipientEncryptionTest.class.getCanonicalName(),
            "The magic words are squeamish ossifrage".getBytes(Constants.ASCII));
        final List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        final AesKey aesKey = AesKey.generateAESKey();
        System.out.println("Master key:");
        ConvertUtils.prettyPrint(AesKey.class, aesKey, System.out);
        ConvertUtils.prettyPrint(AesKeyId.class, aesKey.getKeyId(), System.out);
        for (final PublicEncryptionKey pKey : publicKeys) {
            final AesKey rKey = pKey.setupEncrypt(sequenceItems);
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
        for (final PrivateEncryptionKey k: keys) {
            final InferenceEngine inferenceEngine = new InferenceEngine();
            inferenceEngine.process(k);
            inferenceEngine.process(packet);
            final List<SimpleMessage> messages = inferenceEngine.getMessages();
            assertEquals(1, messages.size());
            final SimpleMessage result = messages.get(0);
            assertEquals(message, result);
        }
    }


}
