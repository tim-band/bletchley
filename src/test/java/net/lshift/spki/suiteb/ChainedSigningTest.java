package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertEquals;

import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

public class ChainedSigningTest extends UsesSimpleMessage
{
    @Test
    public void testSequenceBasedSigningAndVerification() throws InvalidInputException {
        PrivateSigningKey privateKey = PrivateSigningKey.generate();
        privateKey = roundTrip(PrivateSigningKey.class, privateKey);
        final PublicSigningKey publicKey = privateKey.getPublicKey();
        final Action message = SimpleMessage.makeMessage(this.getClass());
        final Sequence subsequence = SequenceUtils.sequence(
            DigestSha384.digest(message),
            publicKey.keyId // Some rubbish
        );
        Sequence sequence = SequenceUtils.sequence(
            publicKey,
            privateKey.sign(subsequence),
            subsequence,
            message);
        sequence = roundTrip(Sequence.class, sequence);

        final InferenceEngine inference = new InferenceEngine();
        inference.process(sequence);
        final List<ActionType> signedBy = inference.getSignedBy(publicKey.getKeyId());
        assertEquals(1, signedBy.size());
        assertEquals(message.getPayload(), signedBy.get(0));
    }
}
