package net.lshift.spki.suiteb;

import org.bouncycastle.crypto.CipherParameters;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.proto.ProtobufHelper;
import net.lshift.spki.suiteb.sexpstructs.EcdhPublicKey;

/**
 * A public key for encrypting data.
 */
public class PublicEncryptionKey 
extends PublicKey 
implements SequenceItem
{
    PublicEncryptionKey(final CipherParameters publicKey) {
        super(publicKey);
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        engine.addPublicEncryptionKey(this);
    }

    public static PublicEncryptionKey fromProtobuf(SuiteBProto.EcPoint point)
            throws CryptographyException {
        return new PublicEncryptionKey(new EcdhPublicKey(ProtobufHelper.ecPointFromProtobuf(point)).getParameters());
    }

    public static PublicEncryptionKey fromProtobuf(SuiteBProto.PublicEncryptionKey pb) 
    throws CryptographyException {
        return PublicEncryptionKey.fromProtobuf(pb.getPoint());
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobuf() {
        return SuiteBProto.SequenceItem.newBuilder()
                .setPublicEncryptionKey(SuiteBProto.PublicEncryptionKey.newBuilder()
                        .setPoint(new EcdhPublicKey(this.publicKey).toProtobuf()));
    }
}
