package net.lshift.spki.suiteb;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.Constants;
import net.lshift.spki.suiteb.sexpstructs.SequenceConversion;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

import org.junit.Test;

public class MultipleRecipientEncryptionTest
{
    @Test
    public void test()
    {
        List<PrivateEncryptionKey> keys = new ArrayList<PrivateEncryptionKey>();
        List<PublicEncryptionKey> publicKeys = new ArrayList<PublicEncryptionKey>();
        for (int i = 0; i < 3; i++) {
            PrivateEncryptionKey k = PrivateEncryptionKey.generate();
            keys.add(k);
            publicKeys.add(k.getPublicKey());
        }
        SimpleMessage message = new SimpleMessage(
            MultipleRecipientEncryptionTest.class.getCanonicalName(),
            "The magic words are squeamish ossifrage".getBytes(Constants.UTF8));
        SequenceItem packet
            = MultipleRecipient.encrypt(publicKeys, message);
        packet = RoundTrip.roundTrip(
            SequenceItem.class, packet);
        for (PrivateEncryptionKey k: keys) {
            SimpleMessage result = MultipleRecipient.decrypt(k, packet);
            assertEquals(message, result);
        }
    }

    static {
        SequenceConversion.ensureInstalled();
    }
}
