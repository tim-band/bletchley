package net.lshift.spki.suiteb;

import java.math.BigInteger;

import net.lshift.spki.convert.PackConvertible;
import net.lshift.spki.suiteb.sexpstructs.ECDSAPrivateKey;
import net.lshift.spki.suiteb.sexpstructs.ECDSASignature;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * A private key for signing
 */
public class PrivateSigningKey extends PackConvertible
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

    @Override
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

    public ECDSASignature rawSignature(DigestSha384 digest)
    {
        BigInteger[] signature = signer.generateSignature(digest.getBytes());
        return new ECDSASignature(signature[0], signature[1]);
    }

    public SequenceItem sign(SequenceItem item)
    {
        DigestSha384 digest = DigestSha384.digest(SequenceItem.class, item);
        return new Signature(digest, getPublicKey().getKeyId(),
            rawSignature(digest));
    }
}
