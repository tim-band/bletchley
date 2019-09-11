package net.lshift.spki.suiteb;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;

public class UntrustedCondition
    implements Condition {
    public static final UntrustedCondition UNTRUSTED = new UntrustedCondition();

    private UntrustedCondition() {
        // use static instance
    }

    @Override
    public <ActionType extends Message> boolean allows(
            final InferenceEngine<ActionType> inferenceEngine, 
            final ActionType payload) {
        return false;
    }

    public static Condition nullMeansUntrusted(final Condition condition) {
        return condition != null ? condition : UNTRUSTED;
    }

    @Override
    public SuiteBProto.Condition.Builder toProtobuf() {
        return SuiteBProto.Condition.newBuilder().setUntrusted(
                SuiteBProto.UntrustedCondition.getDefaultInstance());
    }
}
