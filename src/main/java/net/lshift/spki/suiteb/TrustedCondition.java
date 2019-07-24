package net.lshift.spki.suiteb;

import com.google.protobuf.Message;

/**
 * Condition that always passes
 */
public class TrustedCondition extends InternalCondition {
    public static final TrustedCondition TRUSTED = new TrustedCondition();

    private TrustedCondition() {
        // use static instance
    }

    @Override
    public <ActionType extends Message> boolean allows(
            final InferenceEngine<ActionType> inferenceEngine, 
            final ActionType payload) {
        return true;
    }
}
