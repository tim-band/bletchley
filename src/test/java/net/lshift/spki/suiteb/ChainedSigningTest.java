package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.DigestSha384.digest;
import static net.lshift.spki.suiteb.InferenceEngineTest.checkMessage;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;

import org.junit.Test;

public class ChainedSigningTest extends UsesSimpleMessage
{
    @Test
    public void testSequenceBasedSigningAndVerification() throws InvalidInputException {
        PrivateSigningKey privateKey = PrivateSigningKey.generate();
        // privateKey = roundTrip(PrivateSigningKey.class, privateKey);
        final PublicSigningKey publicKey = privateKey.getPublicKey();
        final Action message = makeMessage();
        Sequence sequence = sequence(
            publicKey,
            signed(privateKey, sequence(
                digest(message),
                publicKey.getKeyId() // Some rubbish
            )),
            signed(message));
        sequence = roundTrip(Sequence.class, sequence);

        final InferenceEngine inference = newEngine();
        inference.processTrusted(publicKey.getKeyId());
        inference.process(sequence);
        checkMessage(inference, message);
    }
}
