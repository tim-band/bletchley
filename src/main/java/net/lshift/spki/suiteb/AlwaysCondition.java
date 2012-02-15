package net.lshift.spki.suiteb;

/**
 * Condition that always passes
 */
public class AlwaysCondition
    implements Condition {
    public static AlwaysCondition ALWAYS = new AlwaysCondition();

    private AlwaysCondition() {
        // use static instance
    }

    @Override
    public boolean allows(InferenceEngine inferenceEngine, ActionType payload) {
        return true;
    }
}
