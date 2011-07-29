package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

public class EncryptionCacheTest extends UsesSimpleMessage {
    @Test
    public void test() throws InvalidInputException
    {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        privateKey = roundTrip(PrivateEncryptionKey.class, privateKey);
        PublicEncryptionKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicEncryptionKey.class, publicKey);
        final Action message = SimpleMessage.makeMessage(this.getClass());
        final EncryptionCache cache = new EncryptionCache();
        final EncryptionSetup aesKey = cache.setupEncrypt(publicKey);
        final EncryptionSetup aesKey2 = cache.setupEncrypt(publicKey);
        assertSame(aesKey, aesKey2);
        Sequence sequence = SequenceUtils.sequence(
            aesKey.encryptedKey,
            aesKey.key.encrypt(message));
        sequence = roundTrip(Sequence.class, sequence);
        final InferenceEngine inferenceEngine = new InferenceEngine();
        inferenceEngine.process(privateKey);
        inferenceEngine.process(sequence);
        final List<ActionType> messages = inferenceEngine.getActions();
        assertEquals(1, messages.size());
        assertEquals(message.getPayload(), messages.get(0));
    }
}
