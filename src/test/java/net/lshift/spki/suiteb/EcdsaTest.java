package net.lshift.spki.suiteb;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.junit.Test;

/**
 * Exercise doing ECDSA using the BouncyCastle API.
 */
public class EcdsaTest
{
    @Test
    public void curveTest() {
        final X9ECParameters curve = NISTNamedCurves.getByName("P-384");
        final ECDomainParameters domainParameters = new ECDomainParameters(
                curve.getCurve(), curve.getG(), curve.getN());
        final SecureRandom random = new SecureRandom();
        final ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(domainParameters, random));
        final AsymmetricCipherKeyPair senderPair = gen.generateKeyPair();
        final ECDSASigner signer = new ECDSASigner();
        signer.init(true, senderPair.getPrivate());
        final byte[] message = "The magic words are squeamish ossifrage".getBytes(
                StandardCharsets.US_ASCII);
        final SHA384Digest digester = new SHA384Digest();
        digester.update(message, 0, message.length);
        final byte[] digest = new byte[digester.getDigestSize()];
        digester.doFinal(digest, 0);
        final BigInteger[] signature = signer.generateSignature(digest);
        final ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, senderPair.getPublic());
        assertTrue(verifier.verifySignature(digest, signature[0], signature[1]));
    }
}
