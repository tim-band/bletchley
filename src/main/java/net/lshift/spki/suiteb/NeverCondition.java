package net.lshift.spki.suiteb;

public class NeverCondition
    implements Condition {
    public static NeverCondition NEVER = new NeverCondition();

    private NeverCondition() {
        // use static instance
    }

    @Override
    public boolean allows(final InferenceEngine inferenceEngine, final ActionType payload) {
        return false;
    }

    public static Condition nullMeansNever(final Condition condition) {
        return condition != null ? condition : NEVER;
    }
}
