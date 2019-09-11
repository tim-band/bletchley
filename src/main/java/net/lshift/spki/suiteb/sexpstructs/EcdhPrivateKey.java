package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.ParseException;
import net.lshift.spki.suiteb.CryptographyException;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * Serialization format for private encryption keys
 */
public class EcdhPrivateKey {
    public final PublicEncryptionKey publicKey;
    public final BigInteger d;

    public EcdhPrivateKey(final PublicEncryptionKey publicKey, final BigInteger d) {
        this.publicKey = publicKey;
        this.d = d;
    }

    public SuiteBProto.EcdhPrivateKey.Builder toProtobuf() {
        return SuiteBProto.EcdhPrivateKey.newBuilder()
                .setPublicKey(new EcdhPublicKey(publicKey.publicKey).toProtobuf())
                .setD(ProtobufHelper.toProtobuf(d));
    }

    public static EcdhPrivateKey fromProtobuf(SuiteBProto.PrivateEncryptionKey privateEncryptionKey)
            throws ParseException, CryptographyException {
        return new EcdhPrivateKey(PublicEncryptionKey.fromProtobuf(privateEncryptionKey.getKey().getPublicKey()),
                ProtobufHelper.toBigInteger(privateEncryptionKey.getKey().getD()));
    }
}
