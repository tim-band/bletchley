package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;

import org.junit.Test;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;

public class PKEncryptionTest extends UsesSimpleMessage {
    @Test
    public void test() throws InvalidInputException
    {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        privateKey = roundTrip(PrivateEncryptionKey.class, privateKey);
        PublicEncryptionKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicEncryptionKey.class, publicKey);
        final Action message = makeMessage();
        final EncryptionCache ephemeral = EncryptionCache.ephemeralKey();
        Sequence sequence = sequence(
            ephemeral.getPublicKey(),
            ephemeral.encrypt(publicKey, message));
        sequence = roundTrip(Sequence.class, sequence);
        final InferenceEngine inferenceEngine = newEngine();
        inferenceEngine.process(privateKey);
        inferenceEngine.processTrusted(sequence);
        checkMessage(inferenceEngine, message);
    }
}
