package net.lshift.spki.suiteb;

import java.math.BigInteger;

import net.lshift.spki.convert.PackConvertible;
import net.lshift.spki.suiteb.sexpstructs.EcdsaAPrivateKey;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;
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

    public static PrivateSigningKey unpack(EcdsaAPrivateKey sexp)
    {
        return new PrivateSigningKey(sexp.getKeypair());
    }

    @Override
    public EcdsaAPrivateKey pack()
    {
        return new EcdsaAPrivateKey(keyPair);
    }

    public PublicSigningKey getPublicKey() {
        return new PublicSigningKey(keyPair.getPublic());
    }

    public static PrivateSigningKey generate() {
        return new PrivateSigningKey(Ec.generate());
    }

    public EcdsaSignature rawSignature(DigestSha384 digest)
    {
        BigInteger[] signature = signer.generateSignature(digest.getBytes());
        return new EcdsaSignature(signature[0], signature[1]);
    }

    public SequenceItem sign(SequenceItem item)
    {
        DigestSha384 digest = DigestSha384.digest(SequenceItem.class, item);
        return new Signature(digest, getPublicKey().getKeyId(),
            rawSignature(digest));
    }
}
