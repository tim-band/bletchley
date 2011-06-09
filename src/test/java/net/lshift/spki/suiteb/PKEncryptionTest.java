package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertEquals;

import java.util.List;

import net.lshift.spki.Constants;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.junit.Test;

public class PKEncryptionTest {
    @Test
    public void test() throws InvalidInputException
    {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        privateKey = roundTrip(PrivateEncryptionKey.class, privateKey);
        PublicEncryptionKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicEncryptionKey.class, publicKey);
        final SimpleMessage message = new SimpleMessage(
            PKEncryptionTest.class.getCanonicalName(),
            "The magic words are squeamish ossifrage".getBytes(Constants.ASCII));
        final EncryptionSetup aesKey = publicKey.setupEncrypt();
        Sequence sequence = SequenceUtils.sequence(
            aesKey.encryptedKey,
            aesKey.key.encrypt(message));
        sequence = roundTrip(Sequence.class, sequence);
        final InferenceEngine inferenceEngine = new InferenceEngine();
        inferenceEngine.process(privateKey);
        inferenceEngine.process(sequence);
        final List<SimpleMessage> messages = inferenceEngine.getMessages();
        assertEquals(1, messages.size());
        assertEquals(message, messages.get(0));
    }

}
