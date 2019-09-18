package net.lshift.spki.suiteb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.SequenceItem.Builder;
import net.lshift.spki.InvalidInputException;

/**
 * SequenceItem container for something the application might act on.
 */
public class Action implements SequenceItem {
    private static final Logger LOG = LoggerFactory.getLogger(Action.class);
    private final Message payload;

    public Action(final Message payload) {
        this.payload = payload;
    }

    public Message getPayload() {
        return payload;
    }

    @Override
    public void process(
            final InferenceEngine engine, 
            final Condition trust) throws InvalidInputException {
        if (trust.allows(engine, payload)) {
            LOG.debug("Trusting message");
            engine.addAction(payload);
        } else {
            LOG.debug("Discarding untrusted message");
        }

    }

    @Override
    public Builder toProtobuf() {
        return SuiteBProto.SequenceItem.newBuilder()
                .setAction(SuiteBProto.Action.newBuilder()
                        .setName(this.payload.getDescriptorForType().getFullName())
                        .setValue(this.payload.toByteString()));
    }

}
