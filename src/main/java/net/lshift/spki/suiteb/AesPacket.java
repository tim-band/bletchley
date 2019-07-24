package net.lshift.spki.suiteb;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;

/**
 * A SequenceItem encrypted with AES/GCM.
 */
@Convert.ByPosition(name = "aes-gcm-encrypted",
fields={"keyId", "nonce", "ciphertext"})
public class AesPacket implements SequenceItem {
    private static final Logger LOG
    = LoggerFactory.getLogger(AesPacket.class);

    public final AesKeyId keyId;
    public final byte[] nonce;
    public final byte[] ciphertext;

    public AesPacket(final AesKeyId keyId,
                     final byte[] nonce,
                     final byte[] ciphertext) {
        this.keyId = keyId;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }

    @Override
    public <ActionType extends Message> void process(final InferenceEngine<ActionType> engine, final Condition trust, Class<ActionType> actionType)
                    throws InvalidInputException {
        final AesKey key = engine.getAesKey(keyId);
        if (key != null) {
            final SequenceItem contents = key.decrypt(this);
            LOG.debug("Decryption successful");
            engine.process(contents, trust);
        } else {
            LOG.debug("Key not known");
        }
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobufSequenceItem() {
        return SuiteBProto.SequenceItem.newBuilder().setAesPacket(
                SuiteBProto.AesPacket.newBuilder()
                .setKeyId(keyId.toProtobuf())
                .setNonce(ByteString.copyFrom(nonce))
                .setCiphertext(ByteString.copyFrom(ciphertext)));
    }
}
