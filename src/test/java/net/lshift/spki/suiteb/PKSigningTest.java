package net.lshift.spki.suiteb;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import net.lshift.spki.convert.UsesSimpleMessage;

public class PKSigningTest extends UsesSimpleMessage {
    @Test
    public void test() {
        PrivateSigningKey privateKey = PrivateSigningKey.generate();
        // privateKey = roundTrip(PrivateSigningKey.class, privateKey);
        PublicSigningKey publicKey = privateKey.getPublicKey();
        publicKey = roundTrip(PublicSigningKey.class, publicKey);
        final Action message = makeMessage();
        final DigestSha384 digest = DigestSha384.digest(message);
        final Signature signature = roundTrip(Signature.class,
            new Signature(digest, publicKey.getKeyId(), privateKey.rawSignature(digest)));
        assertTrue(publicKey.validate(digest, signature.rawSignature));
    }
}
