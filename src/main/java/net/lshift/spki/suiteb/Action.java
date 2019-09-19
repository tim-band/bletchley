package net.lshift.spki.suiteb;

import java.text.MessageFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.Any;
import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.SequenceItem.Builder;
import net.lshift.spki.InvalidInputException;

/**
 * SequenceItem container for something the application might act on.
 */
public class Action implements SequenceItem {
    private static final Logger LOG = LoggerFactory.getLogger(Action.class);
    public static final String TYPE_PREFIX = "net.lshift.bletchley.action";
    private final Message payload;

    public static String typeUrl(String typeName) {
        return String.join("/", TYPE_PREFIX, typeName);
    }
    
    public static String typeName(String typeUrl) throws InvalidInputException {
        String [] parts = typeUrl.split("/");
        if(parts.length != 2 || !parts[0].equals(TYPE_PREFIX)) {
            throw new InvalidInputException(MessageFormat.format(
            "invalid typeUrl {0}. typeUrl must be of the form {1}/typeName",
            TYPE_PREFIX, typeUrl));
        }
        
        return parts[1];
    }

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
                .setAction(SuiteBProto.Action.newBuilder().setAccept(
                        Any.newBuilder()
                        .setTypeUrl(typeUrl(this.payload.getDescriptorForType().getFullName()))
                        .setValue(this.payload.toByteString())));
    }

}
