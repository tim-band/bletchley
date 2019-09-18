package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.ConditionJoiner.and;

import java.util.Arrays;
import java.util.List;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.Limit.Builder;
import net.lshift.spki.InvalidInputException;

public class Limit implements SequenceItem {
    public final SequenceItem subject;
    public final List<Condition> conditions;

    public Limit(final SequenceItem subject, final List<Condition> conditions) {
        this.subject = subject;
        this.conditions = conditions;
    }

    @Override
    public void process(
            final InferenceEngine engine, 
            final Condition trust)
        throws InvalidInputException {
        engine.process(subject, and(trust, and(conditions)));
    }

    public static Limit limit(
        final SequenceItem subject,
        final Condition... conditions) {
        return new Limit(subject, Arrays.asList(conditions));
    }

    @Override
    public SuiteBProto.SequenceItem.Builder toProtobuf() {
        Builder builder = SuiteBProto.Limit.newBuilder().setSubject(subject.toProtobuf());
        for(Condition condition: conditions) {
            builder.addCondition(condition.toProtobuf());
        }
        return SuiteBProto.SequenceItem.newBuilder().setLimit(builder);
    }
}
