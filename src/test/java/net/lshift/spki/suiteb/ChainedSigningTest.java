package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertEquals;

import java.util.List;

import net.lshift.spki.Constants;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.junit.Test;

public class ChainedSigningTest
{
    @Test
    public void testSequenceBasedSigningAndVerification() throws InvalidInputException {
        PrivateSigningKey privateKey = PrivateSigningKey.generate();
        privateKey = roundTrip(PrivateSigningKey.class, privateKey);
        final PublicSigningKey publicKey = privateKey.getPublicKey();
        final SimpleMessage message = new SimpleMessage(
            ChainedSigningTest.class.getCanonicalName(),
            "The magic words are squeamish ossifrage".getBytes(Constants.ASCII));
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
        final List<SequenceItem> signedBy = inference.getSignedBy(publicKey.getKeyId());
        assertEquals(1, signedBy.size());
        assertEquals(message, signedBy.get(0));
    }
}
