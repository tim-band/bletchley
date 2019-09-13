package net.lshift.spki.suiteb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * An ECDH session key packet
 */
public class EcdhItem implements SequenceItem {
    private static final Logger LOG = LoggerFactory.getLogger(EcdhItem.class);

    public final DigestSha384 sender;
    public final DigestSha384 recipient;

    public EcdhItem(final DigestSha384 sender, final DigestSha384 recipient) {
        this.sender = sender;
        this.recipient = recipient;
    }

    @Override
    public <ActionType extends Message> void process(
            final InferenceEngine<ActionType> engine, 
            final Condition trust, 
            Class<ActionType> actionType)
                    throws InvalidInputException {
        final PrivateEncryptionKey privs = engine.getPrivateEncryptionKey(sender);
        final PrivateEncryptionKey privr = engine.getPrivateEncryptionKey(recipient);
        final PublicEncryptionKey pubs = engine.getPublicEncryptionKey(sender);
        final PublicEncryptionKey pubr = engine.getPublicEncryptionKey(recipient);
        if (privr != null && pubs != null) {
            engine.process(privr.getKeyAsReceiver(pubs), trust);
        } else if (privs != null && pubr != null) {
            engine.process(privs.getKeyAsSender(pubr), trust);
        } else {
            LOG.debug("No ephemeral key derived");
            if(privs == null) LOG.debug("No sender private encryption key");
            if(privr == null) LOG.debug("No receiver private encryption key");
            if(pubs == null) LOG.debug("No sender public encryption key");
            if(pubr == null) LOG.debug("No receiver public encryption key");
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
                        .setRecipient(recipient.toProtobufHash()));
    }
}
