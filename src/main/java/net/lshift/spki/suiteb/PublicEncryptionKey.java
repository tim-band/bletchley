package net.lshift.spki.suiteb;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.SequenceItem.Builder;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.convert.Convert.ConvertClass;
import net.lshift.spki.convert.ListStepConverter;
import net.lshift.spki.convert.ProtobufConvert;
import net.lshift.spki.suiteb.proto.ProtobufHelper;
import net.lshift.spki.suiteb.sexpstructs.EcdhPublicKey;

import org.bouncycastle.crypto.CipherParameters;

import com.google.protobuf.Message;

/**
 * A public key for encrypting data.
 */
@ConvertClass(PublicEncryptionKey.Step.class)
public class PublicEncryptionKey 
extends PublicKey 
implements SequenceItem ,
ProtobufConvert<SuiteBProto.PublicEncryptionKey.Builder>
{
    PublicEncryptionKey(final CipherParameters publicKey) {
        super(publicKey);
    }

    public static class Step
        extends ListStepConverter<PublicEncryptionKey, EcdhPublicKey> {
        public Step() { super(PublicEncryptionKey.class, EcdhPublicKey.class); }

        @Override
        public EcdhPublicKey stepIn(final PublicEncryptionKey o) {
            return new EcdhPublicKey(o.publicKey);
        }

        @Override
        public PublicEncryptionKey stepOut(final EcdhPublicKey s)
            throws ParseException {
            return new PublicEncryptionKey(s.getParameters());
        }
    }

    @Override
    public <ActionType extends Message> void process(final InferenceEngine<ActionType> engine, final Condition trust, Class<ActionType> actionType)
        throws InvalidInputException {
        engine.addPublicEncryptionKey(this);
    }

    public static PublicEncryptionKey fromProtobuf(SuiteBProto.EcPoint point)
            throws ParseException, CryptographyException {
        return ProtobufHelper.publicEncryptionKeyConverter.stepOut(new EcdhPublicKey(ProtobufHelper.ecPointFromProtobuf(point)));
    }

    public static PublicEncryptionKey fromProtobuf(SuiteBProto.PublicEncryptionKey pb) 
    throws ParseException, CryptographyException {
        return PublicEncryptionKey.fromProtobuf(pb.getPoint());
    }

    @Override
    public Builder toProtobufSequenceItem() {
        return SuiteBProto.SequenceItem.newBuilder()
                .setPublicEncryptionKey(this.toProtobuf());
    }

    @Override
    public SuiteBProto.PublicEncryptionKey.Builder toProtobuf() {
        return SuiteBProto.PublicEncryptionKey.newBuilder()
                .setPoint(ProtobufHelper.publicEncryptionKeyConverter.stepIn(this).toProtobuf());
    }
}
