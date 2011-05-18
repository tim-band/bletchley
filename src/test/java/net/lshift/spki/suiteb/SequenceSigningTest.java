package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.Constants;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceConversion;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.junit.Test;


public class SequenceSigningTest
{
    @Test
    public void testSequenceBasedSigningAndVerification() {
        PrivateSigningKey privateKey = PrivateSigningKey.generate();
        privateKey = roundTrip(PrivateSigningKey.class, privateKey);
        PublicSigningKey publicKey = privateKey.getPublicKey();
        SimpleMessage message = new SimpleMessage(
            SequenceSigningTest.class.getCanonicalName(),
            "The magic words are squeamish ossifrage".getBytes(Constants.UTF8));
        DigestSha384 digest = DigestSha384.digest(SimpleMessage.class, message);
        List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        sequenceItems.add(publicKey.pack());
        sequenceItems.add(message);
        sequenceItems.add(privateKey.sign(message));
        Sequence sequence = new Sequence(sequenceItems);
        sequence = roundTrip(Sequence.class, sequence);

        InferenceEngine inference = new InferenceEngine();
        inference.process(sequence);
        List<SequenceItem> signedBy = inference.getSignedBy(publicKey.getKeyId());
        assertEquals(1, signedBy.size());
        assertEquals(message, signedBy.get(0));
    }

    static {
        SequenceConversion.ensureInstalled();
    }
}
