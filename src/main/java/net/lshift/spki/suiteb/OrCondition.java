package net.lshift.spki.suiteb;

public class OrCondition
    implements Condition {
    private final Condition[] conditions;

    public OrCondition(Condition... conditions) {
        this.conditions = conditions;
    }

    @Override
    public boolean allows(InferenceEngine inferenceEngine, ActionType payload) {
        for (Condition c: conditions) {
            if (c != null && c.allows(inferenceEngine, payload))
                return true;
        }
        return false;
    }
}
