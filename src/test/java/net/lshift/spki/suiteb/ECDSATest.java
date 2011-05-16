package net.lshift.spki.suiteb;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;

import net.lshift.spki.Constants;

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
public class ECDSATest
{
    @Test
    public void curveTest() {
        X9ECParameters curve = NISTNamedCurves.getByName("P-384");
        ECDomainParameters domainParameters = new ECDomainParameters(
                curve.getCurve(), curve.getG(), curve.getN());
        SecureRandom random = new SecureRandom();
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(domainParameters, random));
        AsymmetricCipherKeyPair senderPair = gen.generateKeyPair();
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, senderPair.getPrivate());
        byte[] message = "The magic words are squeamish ossifrage".getBytes(
            Constants.UTF8);
        SHA384Digest digester = new SHA384Digest();
        digester.update(message, 0, message.length);
        byte[] digest = new byte[digester.getDigestSize()];
        digester.doFinal(digest, 0);
        BigInteger[] signature = signer.generateSignature(digest);
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, senderPair.getPublic());
        assertTrue(verifier.verifySignature(digest, signature[0], signature[1]));
    }
}
