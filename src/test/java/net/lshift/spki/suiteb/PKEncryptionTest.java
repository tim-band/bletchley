package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.SExp;
import net.lshift.spki.suiteb.sexpstructs.ECDHMessage;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

public class PKEncryptionTest {
    @Test
    public void test()
    throws IOException, InvalidCipherTextException, ParseException {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        privateKey = roundTrip(privateKey);
        PublicEncryptionKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(publicKey);
        SExp message = atom("The magic words are squeamish ossifrage");
        // FIXME: round trip this
        ECDHMessage encrypted = publicKey.encrypt(message);
        SExp decrypted = privateKey.decrypt(encrypted);
        assertEquals(message, decrypted);
    }
}
