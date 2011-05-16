package net.lshift.spki.suiteb;

import java.math.BigInteger;

import net.lshift.spki.convert.PackConvertable;
import net.lshift.spki.suiteb.sexpstructs.ECDSAPrivateKey;
import net.lshift.spki.suiteb.sexpstructs.ECDSASignature;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * A private key for signing
 */
public class PrivateSigningKey extends PackConvertable
{
    private final AsymmetricCipherKeyPair keyPair;
    private final ECDSASigner signer = new ECDSASigner();

    private PrivateSigningKey(AsymmetricCipherKeyPair keyPair) {
        super();
        this.keyPair = keyPair;
        signer.init(true, keyPair.getPrivate());
    }

    public static PrivateSigningKey unpack(ECDSAPrivateKey sexp)
    {
        return new PrivateSigningKey(sexp.getKeypair());
    }

    public ECDSAPrivateKey pack()
    {
        return new ECDSAPrivateKey(keyPair);
    }

    public PublicSigningKey getPublicKey() {
        return new PublicSigningKey(keyPair.getPublic());
    }

    public static PrivateSigningKey generate() {
        return new PrivateSigningKey(EC.generate());
    }

    public ECDSASignature sign(DigestSha384 digest)
    {
        BigInteger[] signature = signer.generateSignature(digest.getBytes());
        return new ECDSASignature(signature[0], signature[1]);
    }
}
