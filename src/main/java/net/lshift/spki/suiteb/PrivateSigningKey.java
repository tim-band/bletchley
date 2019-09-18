package net.lshift.spki.suiteb;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

import net.lshift.bletchley.suiteb.proto.PrivateSigningKeyProto;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ProtobufConvertible;
import net.lshift.spki.suiteb.sexpstructs.EcdsaPrivateKey;
import net.lshift.spki.suiteb.sexpstructs.EcdsaSignature;

/**
 * A private key for signing
 */
@ProtobufConvertible.ProtobufClass(PrivateSigningKeyProto.PrivateSigningKey.class)
public class PrivateSigningKey
implements ProtobufConvertible<PrivateSigningKeyProto.PrivateSigningKey.Builder> {
    private final PublicSigningKey publicKey;
    private final AsymmetricCipherKeyPair keyPair;
    private final ECDSASigner signer = new ECDSASigner();

    private PrivateSigningKey(
            final PublicSigningKey publicKey,
            final AsymmetricCipherKeyPair keyPair) {
        if(publicKey == null) {
            throw new NullPointerException("publicKey");
        }
        
        if(keyPair == null) {
            throw new NullPointerException("keyPair");
        }

        this.publicKey = publicKey;
        this.keyPair = keyPair;
        signer.init(true, keyPair.getPrivate());
    }

    public PublicSigningKey getPublicKey() {
        return publicKey;
    }

    public static PrivateSigningKey generate() {
        final AsymmetricCipherKeyPair keyPair = Ec.generate();
        return new PrivateSigningKey(
            new PublicSigningKey(keyPair.getPublic()),
            keyPair);
    }

    public EcdsaSignature rawSignature(final DigestSha384 digest) {
        final BigInteger[] signature = signer.generateSignature(digest.getBytes());
        return new EcdsaSignature(signature[0], signature[1]);
    }

    public SequenceItem signDigest(final DigestSha384 digest) {
        return new Signature(digest, getPublicKey().getKeyId(),
            rawSignature(digest));
    }

    public SequenceItem sign(final SequenceItem item) {
        return signDigest(DigestSha384.digest(item));
    }

    public static PrivateSigningKey fromProtobuf(PrivateSigningKeyProto.PrivateSigningKey pb) 
            throws ParseException, CryptographyException {
        final EcdsaPrivateKey s = EcdsaPrivateKey.fromProtobuf(pb.getKey());
        return new PrivateSigningKey(
        s.publicKey,
        s.publicKey.getKeyPair(s.d));
    }

    @Override
    public PrivateSigningKeyProto.PrivateSigningKey.Builder toProtobuf() {
        return PrivateSigningKeyProto.PrivateSigningKey.newBuilder()
                .setKey(new EcdsaPrivateKey(this.publicKey,
                ((ECPrivateKeyParameters)this.keyPair.getPrivate()).getD()).toProtobuf());
    }
}
