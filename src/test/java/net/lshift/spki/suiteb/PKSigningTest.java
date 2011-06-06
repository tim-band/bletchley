package net.lshift.spki.suiteb;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertTrue;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

import org.junit.Test;

public class PKSigningTest {
    @Test
    public void test() {
        PrivateSigningKey privateKey = PrivateSigningKey.generate();
        privateKey = roundTrip(PrivateSigningKey.class, privateKey);
        PublicSigningKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicSigningKey.class, publicKey);
        Sexp message = atom("The magic words are squeamish ossifrage");
        DigestSha384 digest = DigestSha384.digest(Sexp.class, message);
        EcdsaSignature sigVal = roundTrip(EcdsaSignature.class,
            privateKey.rawSignature(digest));
        assertTrue(publicKey.validate(digest, sigVal));
    }
}
