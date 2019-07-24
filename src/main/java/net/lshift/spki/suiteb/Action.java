package net.lshift.spki.suiteb;

import net.lshift.bletchley.suiteb.proto.SuiteBProto.SequenceItem.Builder;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;

/**
 * SequenceItem container for something the application might act on.
 */
@Convert.ByPosition(name="action", fields={"payload"})
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
    public <ActionType extends Message> void process(
            final InferenceEngine<ActionType> engine, 
            final Condition trust, 
            final Class<ActionType> actionType) throws InvalidInputException {
        try {
            ActionType action = payload.unpack(actionType);
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
    public Builder toProtobufSequenceItem() {
        // TODO Auto-generated method stub
        return null;
    }
}
