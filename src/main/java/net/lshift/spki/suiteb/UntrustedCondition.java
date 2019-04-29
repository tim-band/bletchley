package net.lshift.spki.suiteb;

import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name = "untrusted", fields = {})
public class UntrustedCondition
    implements Condition {
    public static final UntrustedCondition UNTRUSTED = new UntrustedCondition();

    private UntrustedCondition() {
        // use static instance
    }

    @Override
    public boolean allows(final InferenceEngine inferenceEngine, final ActionType payload) {
        return false;
    }

    public static Condition nullMeansUntrusted(final Condition condition) {
        return condition != null ? condition : UNTRUSTED;
    }
}
