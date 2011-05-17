package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertTrue;
import net.lshift.spki.SExp;
import net.lshift.spki.suiteb.sexpstructs.ECDSASignature;

import org.junit.Test;

public class PKSigningTest {
    @Test
    public void test() {
        PrivateSigningKey privateKey = PrivateSigningKey.generate();
        privateKey = roundTrip(PrivateSigningKey.class, privateKey);
        PublicSigningKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicSigningKey.class, publicKey);
        SExp message = atom("The magic words are squeamish ossifrage");
        DigestSha384 digest = DigestSha384.digest(message);
        ECDSASignature sigVal = roundTrip(ECDSASignature.class,
            privateKey.sign(digest));
        assertTrue(publicKey.validate(digest, sigVal));
    }
}
