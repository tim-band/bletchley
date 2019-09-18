package net.lshift.spki.suiteb;

import java.util.Arrays;
import java.util.List;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.Sequence.Builder;
import net.lshift.spki.InvalidInputException;

/**
 * A list of SequenceItems.  Itself a SequenceItem.
 */
public class Sequence implements SequenceItem {
    public final List<SequenceItem> sequence;

    public Sequence(final List<SequenceItem> sequence) {
        this.sequence = sequence;
    }

    public static Sequence of(SequenceItem ... items) {
        return new Sequence(Arrays.asList(items));
    }
    
    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        for (final SequenceItem i: sequence) {
            engine.process(i, trust);
        }
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobuf() {
        Builder builder = SuiteBProto.Sequence.newBuilder();
        sequence.stream().map(SequenceItem::toProtobuf).forEach(builder::addItems);
        return SuiteBProto.SequenceItem.newBuilder().setSequence(builder);
    }
}
