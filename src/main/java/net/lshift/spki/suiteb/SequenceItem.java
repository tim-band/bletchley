package net.lshift.spki.suiteb;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.passphrase.PassphraseProtectedKey;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * Item that can go in a sequence and so be interpreted by the InferenceEngine.
 */
@Convert.Discriminated({
    Action.class,
    AesKey.class,
    AesPacket.class,
    DigestSha384.class,
    EcdhItem.class,
    Limit.class,
    PassphraseProtectedKey.class,
    PrivateEncryptionKey.class,
    PublicEncryptionKey.class,
    PublicSigningKey.class,
    Sequence.class,
    Signature.class,
    Signed.class
})
public interface SequenceItem {

    public <ActionType extends Message> void process(InferenceEngine<ActionType> engine, Condition trust, Class<ActionType> actionType)
        throws InvalidInputException;

    /**
     * Convert this sequence item to it's protocol buffer representation. The result is
     * always wrapped in a discriminator.
     * @return the protocol buffer representation
     */
    public SuiteBProto.SequenceItem.Builder toProtobufSequenceItem();

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
}
