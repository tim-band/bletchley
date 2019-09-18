package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.UsesSimpleMessage;

public class MultipleRecipientEncryptionTest extends UsesSimpleMessage
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
        final Action message = makeMessage();
        final List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        final AesKey aesKey = AesKey.generateAESKey();
        System.out.println("Master key:");
        ConvertUtils.prettyPrint(aesKey, System.out);
        final EncryptionCache ephemeral = EncryptionCache.ephemeralKey();
        sequenceItems.add(ephemeral.getPublicKey());
        for (final PublicEncryptionKey pKey : publicKeys) {
            sequenceItems.add(ephemeral.encrypt(pKey, aesKey));
        }
        sequenceItems.add(aesKey.encrypt(message));
        SequenceItem packet = new Sequence(sequenceItems);
        packet = roundTrip(SequenceItem.class, packet);
        for (final PrivateEncryptionKey k: keys) {
            final InferenceEngine inferenceEngine = newEngine();
            inferenceEngine.process(k);
            inferenceEngine.processTrusted(packet);
            checkMessage(inferenceEngine, message);
        }
    }
}
