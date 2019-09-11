package net.lshift.spki.suiteb.sexpstructs;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * Serialization format for public encryption keys
 */
public class EcdhPublicKey extends EcPublicKey {

    public EcdhPublicKey(final ECPoint point) {
        super(point);
    }

    public EcdhPublicKey(final ECPublicKeyParameters publicKey) {
        super(publicKey);
    }

    public EcdhPublicKey(final AsymmetricCipherKeyPair keyPair) {
        super(keyPair);
    }

    public SuiteBProto.EcPoint.Builder toProtobuf() {
        return ProtobufHelper.toProtobuf(point);
    }
}
