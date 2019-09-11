package net.lshift.spki.suiteb;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import net.lshift.spki.suiteb.sexpstructs.EcdhSharedSecret;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Static convenience functions for working with elliptic curves.
 */
public class Ec {
	private Ec() {
		// This class cannot be instantiated
	}
	
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

    public static ECPublicKeyParameters toECPublicKeyParameters(final ECPoint point) {
        return new ECPublicKeyParameters(point, Ec.DOMAIN_PARAMETERS);
    }

    public static AesKey sessionKey(
            final CipherParameters receiverKey,
            final CipherParameters senderKey,
            final CipherParameters privateKey,
            final ECPublicKeyParameters publicKey
    ) {
        final ECDHBasicAgreement senderAgreement = new ECDHBasicAgreement();
        senderAgreement.init(privateKey);
        final EcdhSharedSecret sharedSecret = new EcdhSharedSecret(
            ((ECPublicKeyParameters)receiverKey).getQ(),
            ((ECPublicKeyParameters)senderKey).getQ(),
            senderAgreement.calculateAgreement(publicKey));
        final byte [] hash = DigestSha384.digest(sharedSecret);
        return new AesKey(Arrays.copyOf(hash, AesKey.AES_KEY_BYTES));
    }

    public static byte[] randomBytes(final int len) {
        final byte[] res = new byte[len];
        random.nextBytes(res);
        return res;
    }

    /**
     * convert a point into an ECPoint, if it's a valid point on Bletchley's
     * EC curve.
     * @param pointX x coordinate of the point
     * @param pointY y coordinate of the point
     * @return
     * @throws CryptographyException if the point isn't on the curve
     */
    public static ECPoint convert(BigInteger pointX, BigInteger pointY) throws CryptographyException {
        final ECCurve curve = DOMAIN_PARAMETERS.getCurve();
        final ECPoint res = curve.createPoint(pointX, pointY);
        final ECPoint normRes = res.normalize();
        final ECFieldElement x = normRes.getXCoord();
        if (!normRes.getYCoord().square().equals(
            x.multiply(x.square().add(curve.getA())).add(curve.getB()))) {
            throw new CryptographyException("Point is not on curve");
        }
        return res;
    }
}
