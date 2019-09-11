package net.lshift.spki.suiteb;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.SequenceItem.Builder;
import net.lshift.spki.InvalidInputException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;

/**
 * SequenceItem container for something the application might act on.
 */
public class Action implements SequenceItem {
    private static final Logger LOG = LoggerFactory.getLogger(Action.class);
    private final Any payload;

    public Action(final Any payload) {
        this.payload = payload;
    }

    public Any getPayload() {
        return payload;
    }

    @Override
    public <A extends Message> void process(
            final InferenceEngine<A> engine, 
            final Condition trust, 
            final Class<A> actionType) throws InvalidInputException {
        try {
            A action = payload.unpack(actionType);
            if (trust.allows(engine, action)) {
                LOG.debug("Trusting message");
                engine.addAction(action);
            } else {
                LOG.debug("Discarding untrusted message");
            }
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidInputException(e);
        }
    }

    @Override
    public Builder toProtobuf() {
        return SuiteBProto.SequenceItem.newBuilder()
                .setAction(SuiteBProto.Action.newBuilder().setAccept(this.payload));
    }

}
