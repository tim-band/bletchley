package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.Constants;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceConversion;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.junit.Test;

public class PKEncryptionTest {
    @Test
    public void test()
    {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        privateKey = roundTrip(PrivateEncryptionKey.class, privateKey);
        PublicEncryptionKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicEncryptionKey.class, publicKey);
        SimpleMessage message = new SimpleMessage(
            PKEncryptionTest.class.getCanonicalName(),
            "The magic words are squeamish ossifrage".getBytes(Constants.ASCII));
        List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        AesKey aesKey = publicKey.setupEncrypt(sequenceItems);
        sequenceItems.add(aesKey.encrypt(message));
        Sequence sequence = new Sequence(sequenceItems);
        sequence = roundTrip(Sequence.class, sequence);
        InferenceEngine inferenceEngine = new InferenceEngine();
        inferenceEngine.process(privateKey);
        inferenceEngine.process(sequence);
        List<SimpleMessage> messages = inferenceEngine.getMessages();
        assertEquals(1, messages.size());
        assertEquals(message, messages.get(0));
    }

    static {
        SequenceConversion.ensureInstalled();
    }
}
