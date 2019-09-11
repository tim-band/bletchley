package net.lshift.spki.suiteb.sexpstructs;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import net.lshift.bletchley.suiteb.proto.SuiteBProto.EcPoint;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * Serialization format for public sig verification keys
 */
public class EcdsaPublicKey
    extends EcPublicKey {
    public EcdsaPublicKey(final ECPoint point) {
        super(point);
    }

    public EcdsaPublicKey(final ECPublicKeyParameters publicKey) {
        super(publicKey);
    }

    public EcdsaPublicKey(final AsymmetricCipherKeyPair keyPair) {
        super(keyPair);
    }

    public EcPoint.Builder toProtobuf() {
        return ProtobufHelper.toProtobuf(this.point);
    }
}
