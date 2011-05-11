package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.atom;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import net.lshift.spki.Marshal;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SExp;

import org.junit.Test;

public class PKSigningTest {
    @Test
    public void test() throws IOException {
        PrivateSigningKey privateKey = PrivateSigningKey.generate();
        //privateKey = PrivateSigningKey.fromSExp(privateKey.toSExp());
        PublicSigningKey publicKey = privateKey.getPublicKey();
        publicKey = PublicSigningKey.fromSExp(publicKey.toSExp());
        SExp message = atom("The magic words are squeamish ossifrage");
        byte[] digest = Marshal.sha384(message);
        SExp sigVal = privateKey.sign(digest);
        PrettyPrinter.prettyPrint(System.out, sigVal);
        assertTrue(publicKey.validate(digest, sigVal));
    }
}
