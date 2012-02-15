package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AndCondition
    implements Condition {
    private final Condition[] conditions;

    private AndCondition(Condition... conditions) {
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

    private static boolean flattenCondition(
        List<Condition> target,
        Condition condition) {
        if (condition instanceof NeverCondition) {
            return true;
        } else if (condition instanceof AndCondition) {
            for (Condition c: ((AndCondition)condition).conditions) {
                if (flattenCondition(target, c))
                    return true;
            }
            return false;
        } else if (condition instanceof AlwaysCondition) {
            return false;
        } else {
            target.add(condition);
            return false;
        }
    }

    public static Condition and(List<Condition> conditions) {
        ArrayList<Condition> target = new ArrayList<Condition>();
        for (Condition c: conditions) {
            if (flattenCondition(target, c))
                return NeverCondition.NEVER;
        }
        return new AndCondition(target.toArray(new Condition[target.size()]));
    }

    public static Condition and(Condition... conditions) {
        return and(Arrays.asList(conditions));
    }
}
