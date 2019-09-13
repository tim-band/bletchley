package net.lshift.spki.suiteb;

import java.text.MessageFormat;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ProtobufConvert;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * Item that can go in a sequence and so be interpreted by the InferenceEngine.
 */
@ProtobufConvert.ProtobufClass(SuiteBProto.SequenceItem.class)
public interface SequenceItem extends ProtobufConvert<SuiteBProto.SequenceItem.Builder> {

    public <ActionType extends Message> void process(InferenceEngine<ActionType> engine, Condition trust, Class<ActionType> actionType)
        throws InvalidInputException;

    /**
     * Convert this sequence item to it's protocol buffer representation. The result is
     * always wrapped in a discriminator.
     * @return the protocol buffer representation
     */
    public SuiteBProto.SequenceItem.Builder toProtobuf();

    
    
    /**
     * Convert from the protocol buffer representation to the
     * internal representation.
     * @param pb the protocol buffer representation
     * @return the internal representation.
     * @throws InvalidInputException
     */
    public static SequenceItem fromProtobuf(SuiteBProto.SequenceItem pb) throws InvalidInputException {
        switch(pb.getItemCase()) {
        case ACTION:
            return new Action(pb.getAction().getAccept());
        case AES_KEY:
            return new AesKey(pb.getAesKey().getKey().toByteArray());
        case AES_PACKET:
            return new AesPacket(
                    new AesKeyId(pb.getAesPacket().getKeyId().toByteArray()), 
                    pb.getAesPacket().getNonce().toByteArray(),
                    pb.getAesPacket().getCiphertext().toByteArray());
        case HASH:
            return ProtobufHelper.toDigest(pb.getHash());
        case ECDH_ITEM:
            return EcdhItem.fromProtobuf(pb.getEcdhItem());
        case LIMIT:
            return Limit.fromProtobuf(pb.getLimit());
        case PRIVATE_ENCRYPTION_KEY:
            return PrivateEncryptionKey.fromProtobuf(pb.getPrivateEncryptionKey());
        case PUBLIC_ENCRYPTION_KEY:
            return PublicEncryptionKey.fromProtobuf(pb.getPublicEncryptionKey());
        case PUBLIC_SIGNING_KEY:
            return PublicSigningKey.fromProtobuf(pb.getPublicSigningKey());
        case SEQUENCE:
            return Sequence.fromProtobuf(pb.getSequence());
        case SIGNATURE:
            return Signature.fromProtobuf(pb.getSignature());
        case SIGNED:
            return Signed.fromProtobuf(pb.getSigned());
        case ITEM_NOT_SET:
            throw new InvalidInputException("Empty sequence item");
        default:
            throw new InvalidInputException("Unknown sequence item type");
        }
    }

    public static SequenceItem fromProtobuf(byte [] bytes) throws InvalidInputException {
        try {
            return fromProtobuf(SuiteBProto.SequenceItem.parseFrom(bytes));
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidInputException(e); 
        }
    }
    
    public static <T extends SequenceItem> T fromProtobuf(Class<T> required, byte [] bytes) 
            throws InvalidInputException {
        return require(required, fromProtobuf(bytes));
    }

    public static <T extends SequenceItem> T fromProtobuf(
            Class<T> required, 
            SuiteBProto.SequenceItem item) 
            throws InvalidInputException {
        return require(required, fromProtobuf(item));
    }

    public static <T extends SequenceItem> T require(Class<T> required,
            SequenceItem item) {
        if(required.isInstance(item)) {
            return required.cast(item);
        } else {
            throw new IllegalArgumentException(
                    MessageFormat.format(
                            "Required {0} received {1}", 
                            required, 
                            item.getClass()));
        }
    }
}
