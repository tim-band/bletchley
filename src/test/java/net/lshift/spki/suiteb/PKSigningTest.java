package net.lshift.spki.suiteb;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.suiteb.RoundTrip.roundTrip;
import static org.junit.Assert.assertTrue;
import net.lshift.spki.convert.ResetsRegistry;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

import org.junit.Test;

public class PKSigningTest extends ResetsRegistry {
    @Test
    public void test() {
        PrivateSigningKey privateKey = PrivateSigningKey.generate();
        privateKey = roundTrip(PrivateSigningKey.class, privateKey);
        PublicSigningKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicSigningKey.class, publicKey);
        final Sexp message = atom("The magic words are squeamish ossifrage");
        final DigestSha384 digest = DigestSha384.digest(message);
        final EcdsaSignature sigVal = roundTrip(EcdsaSignature.class,
            privateKey.rawSignature(digest));
        assertTrue(publicKey.validate(digest, sigVal));
    }
}
