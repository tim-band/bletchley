package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import java.util.List;

import net.lshift.spki.Constants;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceConversion;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.junit.Test;

public class EncryptionCacheTest {
    @Test
    public void test()
    {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        privateKey = roundTrip(PrivateEncryptionKey.class, privateKey);
        PublicEncryptionKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicEncryptionKey.class, publicKey);
        SimpleMessage message = new SimpleMessage(
            EncryptionCacheTest.class.getCanonicalName(),
            "The magic words are squeamish ossifrage".getBytes(Constants.ASCII));
        EncryptionCache cache = new EncryptionCache();
        EncryptionSetup aesKey = cache.setupEncrypt(publicKey);
        EncryptionSetup aesKey2 = cache.setupEncrypt(publicKey);
        assertSame(aesKey, aesKey2);
        Sequence sequence = SequenceUtils.sequence(
            aesKey.encryptedKey,
            aesKey.key.encrypt(message));
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