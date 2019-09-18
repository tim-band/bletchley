package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;
import static org.junit.Assert.assertSame;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;

import org.junit.Test;

public class EncryptionCacheTest extends UsesSimpleMessage {
    @Test
    public void test() throws InvalidInputException
    {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        privateKey = roundTrip(PrivateEncryptionKey.class, privateKey);
        PublicEncryptionKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicEncryptionKey.class, publicKey);
        final Action message = makeMessage();
        final EncryptionCache cache
            = new EncryptionCache(PrivateEncryptionKey.generate());
        final AesKey aesKey = cache.getKeyAsSender(publicKey);
        final AesKey aesKey2 = cache.getKeyAsSender(publicKey);
        assertSame(aesKey, aesKey2);
        Sequence sequence = SequenceUtils.sequence(
            cache.getPublicKey(),
            cache.ecdhItem(publicKey),
            aesKey.encrypt(message));
        sequence = roundTrip(Sequence.class, sequence);
        final InferenceEngine inferenceEngine = newEngine();
        inferenceEngine.process(privateKey);
        inferenceEngine.processTrusted(sequence);
        checkMessage(inferenceEngine, message);
    }
}
