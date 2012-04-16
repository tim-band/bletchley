package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;
import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static net.lshift.spki.suiteb.sexpstructs.EcdhItem.ecdhItem;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

public class PKEncryptionTest extends UsesSimpleMessage {
    @Test
    public void test() throws InvalidInputException
    {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        privateKey = roundTrip(PrivateEncryptionKey.class, privateKey);
        PublicEncryptionKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicEncryptionKey.class, publicKey);
        final Action message = SimpleMessage.makeMessage(this.getClass());
        final PrivateEncryptionKey ephemeral = PrivateEncryptionKey.generate();
        Sequence sequence = SequenceUtils.sequence(
            ephemeral,
            ecdhItem(ephemeral, publicKey),
            ephemeral.getKeyAsSender(publicKey).encrypt(message));
        sequence = roundTrip(Sequence.class, sequence);
        final InferenceEngine inferenceEngine = new InferenceEngine();
        inferenceEngine.process(privateKey);
        inferenceEngine.processTrusted(sequence);
        checkMessage(inferenceEngine, message);
    }
}
