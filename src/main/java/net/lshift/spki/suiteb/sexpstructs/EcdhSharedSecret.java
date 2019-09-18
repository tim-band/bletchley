package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.EcdhSharedSecret.Builder;
import net.lshift.spki.convert.ProtobufConvertible;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * Serialization format for ECDH shared secret before it's hashed into
 * a GCM key.
 */
@ProtobufConvertible.ProtobufClass(SuiteBProto.EcdhSharedSecret.class)
public class EcdhSharedSecret implements ProtobufConvertible<SuiteBProto.EcdhSharedSecret.Builder> {
    public final ECPoint receiverKey;
    public final ECPoint senderKey;
    public final BigInteger sharedSecret;

    public EcdhSharedSecret(final ECPoint receiverKey,
                            final ECPoint senderKey,
                            final BigInteger sharedSecret) {
        this.receiverKey = receiverKey;
        this.senderKey = senderKey;
        this.sharedSecret = sharedSecret;
    }

    @Override
    public Builder toProtobuf() {
        return SuiteBProto.EcdhSharedSecret.newBuilder()
                .setRecipientKey(ProtobufHelper.toProtobuf(receiverKey))
                .setSenderKey(ProtobufHelper.toProtobuf(senderKey))
                .setSharedSecret(ProtobufHelper.toProtobuf(sharedSecret));
    }
}
