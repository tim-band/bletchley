package net.lshift.spki.suiteb;

public class AndCondition
    implements Condition {
    private final Condition[] conditions;

    public AndCondition(Condition... conditions) {
        this.conditions = conditions;
    }

    @Override
    public boolean allows(InferenceEngine inferenceEngine, ActionType action) {
        for (Condition c: conditions) {
            if (c != null && !c.allows(inferenceEngine, action))
                return false;
        }
        return true;
    }
}
