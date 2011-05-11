package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.list;

import java.math.BigInteger;

import net.lshift.spki.Get;
import net.lshift.spki.SExp;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

public class PrivateSigningKey
{
    private final AsymmetricCipherKeyPair keyPair;
    private final ECDSASigner signer = new ECDSASigner();

    private PrivateSigningKey(AsymmetricCipherKeyPair keyPair) {
        super();
        this.keyPair = keyPair;
        signer.init(true, keyPair.getPrivate());
    }

    public static PrivateSigningKey generate() {
        return new PrivateSigningKey(EC.generate());
    }

    public static PrivateSigningKey fromSExp(SExp sexp)
    {
        ECPublicKeyParameters pk = EC.toECPublicKeyParameters(
            Get.getSExp(EC.ECDSA_PUBLIC_KEY, sexp));
        BigInteger d = Get.getBigInteger("d", sexp);
        ECPrivateKeyParameters privk = new ECPrivateKeyParameters(d,
                        EC.domainParameters);
        return new PrivateSigningKey(new AsymmetricCipherKeyPair(pk, privk));
    }

    public SExp toSExp()
    {
        return list("suiteb-p384-ecdsa-private-key",
            EC.toSExpDSA((ECPublicKeyParameters)keyPair.getPublic()),
            list("d", ((ECPrivateKeyParameters)keyPair.getPrivate()).getD())
        );
    }

    public PublicSigningKey getPublicKey() {
        return new PublicSigningKey(keyPair.getPublic());
    }

    public SExp sign(DigestSha384 digest)
    {
        BigInteger[] signature = signer.generateSignature(digest.getBytes());
        return list("suiteb-p384-ecdsa-signature",
            list("r", signature[0]),
            list("s", signature[1]));
    }
}
