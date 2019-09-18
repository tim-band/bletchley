package net.lshift.spki.suiteb;

import java.text.MessageFormat;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ProtobufConvertible;

/**
 * Item that can go in a sequence and so be interpreted by the InferenceEngine.
 */
@ProtobufConvertible.ProtobufClass(SuiteBProto.SequenceItem.class)
public interface SequenceItem extends ProtobufConvertible<SuiteBProto.SequenceItem.Builder> {

    public void process(InferenceEngine engine, Condition trust)
        throws InvalidInputException;

    /**
     * Convert this sequence item to it's protocol buffer representation. The result is
     * always wrapped in a discriminator.
     * @return the protocol buffer representation
     */
    public SuiteBProto.SequenceItem.Builder toProtobuf();

    public default <T extends SequenceItem> T require(Class<T> required) {
        if(required.isInstance(this)) {
            return required.cast(this);
        } else {
            throw new IllegalArgumentException(
                    MessageFormat.format(
                            "Required {0} received {1}", 
                            required, 
                            this.getClass()));
        }
    }
    

}
