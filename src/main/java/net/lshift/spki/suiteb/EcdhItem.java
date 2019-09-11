package net.lshift.spki.suiteb;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * An ECDH session key packet
 */
public class EcdhItem implements SequenceItem {
    public final DigestSha384 sender;
    public final DigestSha384 recipient;

    public EcdhItem(final DigestSha384 sender, final DigestSha384 recipient) {
        this.sender = sender;
        this.recipient = recipient;
    }

    @Override
    public <ActionType extends Message> void process(final InferenceEngine<ActionType> engine, final Condition trust, Class<ActionType> actionType)
                    throws InvalidInputException {
        final PrivateEncryptionKey privs = engine.getPrivateEncryptionKey(sender);
        final PrivateEncryptionKey privr = engine.getPrivateEncryptionKey(recipient);
        final PublicEncryptionKey pubs = engine.getPublicEncryptionKey(sender);
        final PublicEncryptionKey pubr = engine.getPublicEncryptionKey(recipient);
        if (privr != null && pubs != null) {
            engine.process(privr.getKeyAsReceiver(pubs), trust);
        } else if (privs != null && pubr != null) {
            engine.process(privs.getKeyAsSender(pubr), trust);
        }
    }

    public static SequenceItem fromProtobuf(SuiteBProto.EcdhItem ecdhItem)
            throws InvalidInputException {
        return new EcdhItem(
                ProtobufHelper.toDigest(ecdhItem.getSender()),
                ProtobufHelper.toDigest(ecdhItem.getRecipient()));
    }
    
    public SuiteBProto.SequenceItem.Builder toProtobuf() {
        return SuiteBProto.SequenceItem.newBuilder()
                .setEcdhItem(SuiteBProto.EcdhItem.newBuilder()
                        .setSender(sender.toProtobufHash())
                        .setRecipient(sender.toProtobufHash()));
    }
}
