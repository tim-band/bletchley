// FIXME: this is in the wrong package: it should be up one level
package net.lshift.spki.suiteb.sexpstructs;

import java.math.BigInteger;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * Serialization format for a raw ECDSA signature
 */
public class EcdsaSignature {
    public final BigInteger r;
    public final BigInteger s;

    public EcdsaSignature(final BigInteger r, final BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public SuiteBProto.EcdsaSignature.Builder toProtobuf() {
        return SuiteBProto.EcdsaSignature.newBuilder()
                .setR(ProtobufHelper.toProtobuf(r))
                .setS(ProtobufHelper.toProtobuf(s));
    }
}
