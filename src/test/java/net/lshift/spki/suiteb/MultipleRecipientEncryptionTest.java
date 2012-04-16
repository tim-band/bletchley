package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.sexpstructs.EcdhItem;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

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
        final Action message = SimpleMessage.makeMessage(this.getClass());
        final List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        final AesKey aesKey = AesKey.generateAESKey();
        System.out.println("Master key:");
        ConvertUtils.prettyPrint(AesKey.class, aesKey, System.out);
        ConvertUtils.prettyPrint(AesKeyId.class, aesKey.getKeyId(), System.out);
        final PrivateEncryptionKey ephemeral = PrivateEncryptionKey.generate();
        sequenceItems.add(ephemeral.getPublicKey());
        for (final PublicEncryptionKey pKey : publicKeys) {
            sequenceItems.add(EcdhItem.ecdhItem(ephemeral, pKey));
            final AesKey rKey = ephemeral.getKeyAsSender(pKey);
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
            inferenceEngine.processTrusted(packet);
            checkMessage(inferenceEngine, message);
        }
    }
}
