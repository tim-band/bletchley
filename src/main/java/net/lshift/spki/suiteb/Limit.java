package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.ConditionJoiner.and;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.bletchley.suiteb.proto.SuiteBProto.Limit.Builder;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

public class Limit implements SequenceItem {
    public final SequenceItem subject;
    public final List<Condition> conditions;

    public Limit(final SequenceItem subject, final List<Condition> conditions) {
        this.subject = subject;
        this.conditions = conditions;
    }

    @Override
    public <ActionType extends Message> void process(final InferenceEngine<ActionType> engine, final Condition trust, Class<ActionType> actionType)
        throws InvalidInputException {
        engine.process(subject, and(trust, and(conditions)));
    }

    public static SequenceItem fromProtobuf(
            net.lshift.bletchley.suiteb.proto.SuiteBProto.Limit limit)
            throws InvalidInputException {
        List<Condition> conditions = new ArrayList<>(limit.getConditionCount());
        for(SuiteBProto.Condition condition: limit.getConditionList()) {
            conditions.add(ProtobufHelper.fromProtobuf(condition));
        }
        return new Limit(SequenceItem.fromProtobuf(limit.getSubject()),
                conditions);
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
