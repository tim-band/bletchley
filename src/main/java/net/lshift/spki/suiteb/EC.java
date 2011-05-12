package net.lshift.spki.suiteb;

import java.security.SecureRandom;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.sexpstructs.ECDHPublicKey;
import net.lshift.spki.suiteb.sexpstructs.ECDHSharedSecret;
import net.lshift.spki.suiteb.sexpstructs.ECDSAPublicKey;
import net.lshift.spki.suiteb.sexpstructs.Point;

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
    private static X9ECParameters curve = NISTNamedCurves.getByName("P-384");

    static ECDomainParameters domainParameters = new ECDomainParameters(
            curve.getCurve(), curve.getG(), curve.getN());
    static SecureRandom random = new SecureRandom();
    static ECKeyPairGenerator gen = new ECKeyPairGenerator();
    static {
        gen.init(new ECKeyGenerationParameters(domainParameters, random));
    }

    public static AsymmetricCipherKeyPair generate() {
        return gen.generateKeyPair();
    }

    public static Point toPoint(ECPoint q) {
        return new Point(
            q.getX().toBigInteger(), q.getY().toBigInteger());
    }

    public static ECPoint toECPoint(Point point) {
        return domainParameters.getCurve().createPoint(
                point.getX(), point.getY(), false);
    }

    public static ECDHPublicKey toECDHPublicKey(ECPublicKeyParameters publicKey) {
        return new ECDHPublicKey(toPoint(publicKey.getQ()));
    }

    public static ECDSAPublicKey toECDSAPublicKey(ECPublicKeyParameters publicKey) {
        return new ECDSAPublicKey(toPoint(publicKey.getQ()));
    }

    public static ECPublicKeyParameters toECPublicKeyParameters(
        ECDHPublicKey k
    ) {
        return new ECPublicKeyParameters(
                toECPoint(k.getPoint()),
                domainParameters
        );
    }

    public static ECPublicKeyParameters toECPublicKeyParameters(
        ECDSAPublicKey k
    ) {
        return new ECPublicKeyParameters(
                toECPoint(k.getPoint()),
                domainParameters
        );
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
            toECDHPublicKey((ECPublicKeyParameters)receiverKey),
            toECDHPublicKey((ECPublicKeyParameters)senderKey),
            senderAgreement.calculateAgreement(publicKey));
        DigestSha384 hash = DigestSha384.digest(
            Convert.toSExp(sharedSecret));
        return new KeyParameter(hash.getBytes(), 0, 32);
    }
}
