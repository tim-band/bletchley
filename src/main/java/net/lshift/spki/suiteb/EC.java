package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.Create.list;

import java.math.BigInteger;
import java.security.SecureRandom;

import net.lshift.spki.Get;
import net.lshift.spki.SExp;

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
    public static final String ECDH_PUBLIC_KEY = "suiteb-p384-ecdh-public-key";
    public static final String ECDSA_PUBLIC_KEY = "suiteb-p384-ecdsa-public-key";

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

    public static SExp toSExp(ECPoint q) {
        return list("point",
                list("x", q.getX().toBigInteger()),
                list("y", q.getY().toBigInteger()));
    }

    // FIXME: I'll make these converters strict when I write
    // the annotation-based deserializer.

    public static ECPoint toECPoint(SExp sexp) {
        return domainParameters.getCurve().createPoint(
                Get.getBigInteger("x", sexp),
                Get.getBigInteger("y", sexp),
                false);
    }

    public static SExp toSExpDH(ECPublicKeyParameters publicKey) {
        return list(ECDH_PUBLIC_KEY,
                toSExp(publicKey.getQ()));
    }

    public static SExp toSExpDSA(ECPublicKeyParameters publicKey) {
        return list(ECDSA_PUBLIC_KEY,
                toSExp(publicKey.getQ()));
    }

    public static ECPublicKeyParameters toECPublicKeyParameters(SExp sexp) {
        return new ECPublicKeyParameters(
                toECPoint(Get.getSExp("point", sexp)),
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
        BigInteger sharedSecret = senderAgreement.calculateAgreement(
                publicKey);
        DigestSha384 hash = DigestSha384.digest(
            list("suiteb-p384-ecdh-shared-secret",
                toSExpDH((ECPublicKeyParameters)receiverKey),
                toSExpDH((ECPublicKeyParameters)senderKey),
                atom(sharedSecret)));
        return new KeyParameter(hash.getBytes(), 0, 32);
    }
}
