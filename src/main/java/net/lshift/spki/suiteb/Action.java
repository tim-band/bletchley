package net.lshift.spki.suiteb;

import net.lshift.bletchley.suiteb.proto.SuiteBProto.SequenceItem.Builder;
import net.lshift.spki.convert.Convert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SequenceItem container for something the application might act on.
 */
@Convert.ByPosition(name="action", fields={"payload"})
public class Action implements SequenceItem {
    private static final Logger LOG
        = LoggerFactory.getLogger(Action.class);
    private final ActionType payload;

    public Action(final ActionType payload) {
        this.payload = payload;
    }

    public ActionType getPayload() {
        return payload;
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust) {
        if (trust.allows(engine, payload)) {
            LOG.debug("Trusting message");
            engine.addAction(payload);
        } else {
            LOG.debug("Discarding untrusted message");
        }
    }

    @Override
    public Builder toProtobuf() {
        // TODO Auto-generated method stub
        return null;
    }
}
