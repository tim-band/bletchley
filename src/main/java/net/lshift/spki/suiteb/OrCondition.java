package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class OrCondition
    implements Condition {
    private final Condition[] conditions;

    private OrCondition(Condition... conditions) {
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

    private static boolean flattenCondition(
        List<Condition> target,
        Condition condition) {
        if (condition instanceof AlwaysCondition) {
            return true;
        } else if (condition instanceof OrCondition) {
            for (Condition c: ((OrCondition)condition).conditions) {
                if (flattenCondition(target, c))
                    return true;
            }
            return false;
        } else if (condition instanceof NeverCondition) {
            return false;
        } else {
            target.add(condition);
            return false;
        }
    }

    public static Condition or(List<Condition> conditions) {
        ArrayList<Condition> target = new ArrayList<Condition>();
        for (Condition c: conditions) {
            if (flattenCondition(target, c))
                return AlwaysCondition.ALWAYS;
        }
        return new OrCondition(target.toArray(new Condition[target.size()]));
    }

    public static Condition or(Condition... conditions) {
        return or(Arrays.asList(conditions));
    }
}
