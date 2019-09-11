package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import net.lshift.bletchley.suiteb.proto.SimpleMessageProto.SimpleMessage;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;

/**
 * This is mostly to test interoperation with JCA cryptography for
 * signing. This is also a good indicator of Android interoperation,
 * without introducing a dependency on Android.
 */
public class JcaTest extends UsesSimpleMessage {
    @BeforeClass
    public static void bouncyCastleProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    KeyPair keyPair;
    
    @Before
    public void createKeyPair() throws 
        InvalidAlgorithmParameterException, 
        NoSuchAlgorithmException, 
        NoSuchProviderException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp384r1");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", "BC");
        generator.initialize(ecGenSpec, new SecureRandom());
        keyPair = generator.generateKeyPair();
    }

    @Test
    public void testSequenceBasedSigningAndVerification() throws InvalidInputException {
        final PublicSigningKey publicKey = Jca.importPublicSigningKey(keyPair.getPublic());
        final Action message = makeMessage();
        Sequence sequence = sequence(publicKey, Jca.signed(keyPair, message));
        sequence = roundTrip(Sequence.class, sequence);

        final InferenceEngine<SimpleMessage> inference = newEngine();
        inference.processTrusted(publicKey.getKeyId());
        inference.process(sequence);
        checkMessage(inference, message);
    }
}
