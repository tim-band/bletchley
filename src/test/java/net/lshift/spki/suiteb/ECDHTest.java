package net.lshift.spki.suiteb;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.junit.Test;

/**
 * Exercise the ECDH parts of the bouncycastle API
 */
public class ECDHTest {
    @Test
    public void curveTest() {
        X9ECParameters curve = NISTNamedCurves.getByName("P-384");
        ECDomainParameters domainParameters = new ECDomainParameters(
                curve.getCurve(), curve.getG(), curve.getN());
        SecureRandom random = new SecureRandom();
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(domainParameters, random));
        AsymmetricCipherKeyPair senderPair = gen.generateKeyPair();
        AsymmetricCipherKeyPair receiverPair = gen.generateKeyPair();
        ECDHBasicAgreement senderAgreement = new ECDHBasicAgreement();
        senderAgreement.init(senderPair.getPrivate());
        BigInteger senderResult = senderAgreement.calculateAgreement(
                receiverPair.getPublic());
        ECDHBasicAgreement receiverAgreement = new ECDHBasicAgreement();
        receiverAgreement.init(receiverPair.getPrivate());
        BigInteger receiverResult = receiverAgreement.calculateAgreement(
                senderPair.getPublic());
        assertEquals(senderResult, receiverResult);
        //System.out.println(receiverResult);
    }
}
