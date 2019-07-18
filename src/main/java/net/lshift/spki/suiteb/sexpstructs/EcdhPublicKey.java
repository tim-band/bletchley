package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.EcPoint;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serialization format for public encryption keys
 */
@Convert.RequiresConverter(ECPointConverter.class)
@Convert.ByPosition(name="suiteb-p384-ecdh-public-key", fields={"point"})
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
