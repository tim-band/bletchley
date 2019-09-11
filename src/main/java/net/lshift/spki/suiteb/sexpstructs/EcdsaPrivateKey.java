package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.bletchley.suiteb.proto.PrivateSigningKeyProto;
import net.lshift.spki.suiteb.CryptographyException;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * Serialization format for private signing keys
 */
public class EcdsaPrivateKey {
    public final PublicSigningKey publicKey;
    public final BigInteger d;

    public EcdsaPrivateKey(final PublicSigningKey publicKey, final BigInteger d) {
        this.publicKey = publicKey;
        this.d = d;
    }

    public static EcdsaPrivateKey fromProtobuf(PrivateSigningKeyProto.EcdsaPrivateKey pb) 
            throws CryptographyException {
        return new EcdsaPrivateKey(PublicSigningKey.fromProtobuf(pb.getPublicKey()),
                ProtobufHelper.toBigInteger(pb.getD()));
    }

    public PrivateSigningKeyProto.EcdsaPrivateKey.Builder toProtobuf() {
        return PrivateSigningKeyProto.EcdsaPrivateKey.newBuilder()
                .setPublicKey(new EcdsaPublicKey(publicKey.publicKey).toProtobuf())
                .setD(ProtobufHelper.toProtobuf(d));

    }
}
