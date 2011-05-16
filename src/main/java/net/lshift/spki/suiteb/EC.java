package net.lshift.spki.suiteb;

import java.security.SecureRandom;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.sexpstructs.ECDHSharedSecret;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Static convenience functions for working with elliptic curves.
 */
public class EC {
    private static final X9ECParameters CURVE
        = NISTNamedCurves.getByName("P-384");

    public static final ECDomainParameters DOMAIN_PARAMETERS
        = new ECDomainParameters(
            CURVE.getCurve(), CURVE.getG(), CURVE.getN());
    private static SecureRandom random = new SecureRandom();
    private static ECKeyPairGenerator gen = new ECKeyPairGenerator();
    static {
        gen.init(new ECKeyGenerationParameters(DOMAIN_PARAMETERS, random));
    }

    public static AsymmetricCipherKeyPair generate() {
        return gen.generateKeyPair();
    }

    public static ECPublicKeyParameters toECPublicKeyParameters(ECPoint point)
    {
        return new ECPublicKeyParameters(point, EC.DOMAIN_PARAMETERS);
    }

    public static KeyParameter sessionKey(
            CipherParameters receiverKey,
            CipherParameters senderKey,
            CipherParameters privateKey,
            ECPublicKeyParameters publicKey
    ) {
        ECDHBasicAgreement senderAgreement = new ECDHBasicAgreement();
        senderAgreement.init(privateKey);
        ECDHSharedSecret sharedSecret = new ECDHSharedSecret(
            ((ECPublicKeyParameters)receiverKey).getQ(),
            ((ECPublicKeyParameters)senderKey).getQ(),
            senderAgreement.calculateAgreement(publicKey));
        DigestSha384 hash = DigestSha384.digest(
            Convert.toSExp(ECDHSharedSecret.class, sharedSecret));
        return new KeyParameter(hash.getBytes(), 0, 32);
    }
}
