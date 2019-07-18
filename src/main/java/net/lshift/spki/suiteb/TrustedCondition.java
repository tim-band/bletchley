package net.lshift.spki.suiteb;

/**
 * Condition that always passes
 */
public class TrustedCondition extends InternalCondition {
    public static final TrustedCondition TRUSTED = new TrustedCondition();

    private TrustedCondition() {
        // use static instance
    }

    @Override
    public boolean allows(final InferenceEngine inferenceEngine, final ActionType payload) {
        return true;
    }
}
