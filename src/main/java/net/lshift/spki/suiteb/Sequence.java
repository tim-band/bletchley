package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.List;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.Sequence.Builder;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert.SequenceConverted;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * A list of SequenceItems.  Itself a SequenceItem.
 */
@SequenceConverted("sequence")
public class Sequence
        implements SequenceItem {
    public final List<SequenceItem> sequence;

    public Sequence(final List<SequenceItem> sequence) {
        this.sequence = sequence;
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        for (final SequenceItem i: sequence) {
            engine.process(i, trust);
        }
    }

    public static Sequence fromProtobuf(SuiteBProto.Sequence sequence) throws InvalidInputException {
        // Because of exception handling, this doesn't use Stream#map
        List<SequenceItem> items = new ArrayList<>(sequence.getItemsCount());
        for(SuiteBProto.SequenceItem item: sequence.getItemsList()) {
            items.add(ProtobufHelper.fromProtobuf(item));
        }
        return new Sequence(items);
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobuf() {
        Builder builder = SuiteBProto.Sequence.newBuilder();
        sequence.stream().map(SequenceItem::toProtobuf).forEach(builder::addItems);
        return SuiteBProto.SequenceItem.newBuilder().setSequence(builder);
    }
}
