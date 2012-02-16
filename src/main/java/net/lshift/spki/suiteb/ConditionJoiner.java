package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.List;

public class ConditionJoiner {
    private final boolean disjunction;
    private final Condition identity;
    private final Condition destructor;

    private final List<Condition> terms = new ArrayList<Condition>();
    private boolean destroyed = false;

    private static class AndCondition
    implements Condition {
        private final Condition[] conditions;

        private AndCondition(Condition... conditions) {
            this.conditions = conditions;
        }

        @Override
        public boolean allows(InferenceEngine inferenceEngine, ActionType action) {
            for (Condition c: conditions) {
                if (!c.allows(inferenceEngine, action))
                    return false;
            }
            return true;
        }
    }

    private static class OrCondition
    implements Condition {
        private final Condition[] conditions;

        private OrCondition(Condition... conditions) {
            this.conditions = conditions;
        }

        @Override
        public boolean allows(InferenceEngine inferenceEngine, ActionType payload) {
            for (Condition c: conditions) {
                if (c.allows(inferenceEngine, payload))
                    return true;
            }
            return false;
        }
    }


    private ConditionJoiner(boolean disjunction, Condition identity,
        Condition destructor) {
        super();
        this.disjunction = disjunction;
        this.identity = identity;
        this.destructor = destructor;
    }

    public static ConditionJoiner conjunction() {
        return new ConditionJoiner(
            false, AlwaysCondition.ALWAYS, NeverCondition.NEVER);
    }

    public  static ConditionJoiner disjunction() {
        return new ConditionJoiner(
            true, NeverCondition.NEVER, AlwaysCondition.ALWAYS);
    }

    public void addTerm(Condition term) {
        if (destroyed || term == null || term == identity) {
            // do nothing
        } else if (term == destructor) {
            destroyed = true;
        } else if (!disjunction && term instanceof AndCondition) {
            addTerms(((AndCondition)term).conditions);
        } else if (disjunction && term instanceof OrCondition) {
            addTerms(((OrCondition)term).conditions);
        } else {
            terms.add(term);
        }
    }

    public void addTerms(Condition[] lterms) {
        for (Condition term: lterms) {
            addTerm(term);
        }
    }

    public void addTerms(List<Condition> lterms) {
        for (Condition term: lterms) {
            addTerm(term);
        }
    }

    public Condition getCondition() {
        if (destroyed) {
            return destructor;
        } else if (terms.isEmpty()) {
            return identity;
        } else if (terms.size() == 1) {
            return terms.get(0);
        } else if (!disjunction){
            return new AndCondition(terms.toArray(new Condition[terms.size()]));
        } else {
            return new OrCondition(terms.toArray(new Condition[terms.size()]));
        }
    }

    public static Condition and(Condition... conditions) {
        ConditionJoiner joiner = conjunction();
        joiner.addTerms(conditions);
        return joiner.getCondition();
    }

    public static Condition and(List<Condition> conditions) {
        ConditionJoiner joiner = conjunction();
        joiner.addTerms(conditions);
        return joiner.getCondition();
    }

    public static Condition or(Condition... conditions) {
        ConditionJoiner joiner = disjunction();
        joiner.addTerms(conditions);
        return joiner.getCondition();
    }

    public static Condition or(List<Condition> conditions) {
        ConditionJoiner joiner = disjunction();
        joiner.addTerms(conditions);
        return joiner.getCondition();
    }
}
