package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.atom;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.ParseException;
import net.lshift.spki.SExp;
import net.lshift.spki.suiteb.sexpstructs.MultipleRecipientEncryptedMessage;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

public class MultipleRecipientEncryptionTest
{
    @Test
    public void test()
        throws InvalidCipherTextException,
            ParseException
    {
        List<PrivateEncryptionKey> keys = new ArrayList<PrivateEncryptionKey>();
        List<PublicEncryptionKey> publicKeys = new ArrayList<PublicEncryptionKey>();
        for (int i = 0; i < 3; i++) {
            PrivateEncryptionKey k = PrivateEncryptionKey.generate();
            keys.add(k);
            publicKeys.add(k.getPublicKey());
        }
        SExp message = atom("The magic words are squeamish ossifrage");
        MultipleRecipientEncryptedMessage packet
            = MultipleRecipient.encrypt(SExp.class, publicKeys, message);
        packet = RoundTrip.roundTrip(
            MultipleRecipientEncryptedMessage.class, packet);
        for (PrivateEncryptionKey k: keys) {
            SExp result = MultipleRecipient.decrypt(SExp.class, k, packet);
            assertEquals(message, result);
        }
    }
}
