package net.lshift.spki.suiteb;

import java.math.BigInteger;

import net.lshift.spki.suiteb.sexpstructs.ECDSAPrivateKey;
import net.lshift.spki.suiteb.sexpstructs.ECDSASignature;

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

    public static PrivateSigningKey fromSExp(ECDSAPrivateKey sexp)
    {
        ECPublicKeyParameters pk = EC.toECPublicKeyParameters(
            sexp.getPublicKey());
        BigInteger d = sexp.getD();
        ECPrivateKeyParameters privk = new ECPrivateKeyParameters(d,
                        EC.domainParameters);
        return new PrivateSigningKey(new AsymmetricCipherKeyPair(pk, privk));
    }

    public ECDSAPrivateKey toSExp()
    {
        return new ECDSAPrivateKey(
            EC.toSExpDSA((ECPublicKeyParameters)keyPair.getPublic()),
             ((ECPrivateKeyParameters)keyPair.getPrivate()).getD()
        );
    }

    public PublicSigningKey getPublicKey() {
        return new PublicSigningKey(keyPair.getPublic());
    }

    public ECDSASignature sign(DigestSha384 digest)
    {
        BigInteger[] signature = signer.generateSignature(digest.getBytes());
        return new ECDSASignature(signature[0], signature[1]);
    }
}
