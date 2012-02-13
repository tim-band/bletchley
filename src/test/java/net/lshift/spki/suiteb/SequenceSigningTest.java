package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static net.lshift.spki.suiteb.sexpstructs.Signed.signed;
import static org.junit.Assert.assertEquals;

import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.simplemessage.SimpleMessage;

import org.junit.Test;

public class SequenceSigningTest extends UsesSimpleMessage
{
    @Test
    public void testSequenceBasedSigningAndVerification() throws InvalidInputException {
        PrivateSigningKey privateKey = PrivateSigningKey.generate();
        privateKey = roundTrip(PrivateSigningKey.class, privateKey);
        final PublicSigningKey publicKey = privateKey.getPublicKey();
        final Action message = SimpleMessage.makeMessage(this.getClass());
        Sequence sequence = SequenceUtils.sequence(
            publicKey,
            privateKey.sign(message),
            signed(message));
        sequence = roundTrip(Sequence.class, sequence);

        final InferenceEngine inference = new InferenceEngine();
        inference.addTrustedKey(publicKey.getKeyId());
        inference.process(sequence);
        final List<ActionType> messages = inference.getActions();
        assertEquals(1, messages.size());
        assertEquals(message.getPayload(), messages.get(0));
    }
}
