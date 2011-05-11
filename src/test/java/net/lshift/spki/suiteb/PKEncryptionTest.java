package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.atom;
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.SExp;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

public class PKEncryptionTest {
    @Test
    public void test()
    throws IOException, InvalidCipherTextException, ParseException {
        PrivateEncryptionKey privateKey = PrivateEncryptionKey.generate();
        privateKey = PrivateEncryptionKey.fromSExp(privateKey.toSExp());
        PublicEncryptionKey publicKey = privateKey.getPublicKey();
        publicKey = PublicEncryptionKey.fromSExp(publicKey.toSExp());
        SExp message = atom("The magic words are squeamish ossifrage");
        SExp encrypted = publicKey.encrypt(message);
        //PrettyPrinter.prettyPrint(System.out, encrypted);
        SExp decrypted = privateKey.decrypt(encrypted);
        assertEquals(message, decrypted);
    }
}
