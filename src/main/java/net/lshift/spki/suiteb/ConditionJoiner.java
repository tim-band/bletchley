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

        private AndCondition(final Condition... conditions) {
            this.conditions = conditions;
        }

        @Override
        public boolean allows(final InferenceEngine inferenceEngine, final ActionType action) {
            for (final Condition c: conditions) {
                if (!c.allows(inferenceEngine, action))
                    return false;
            }
            return true;
        }
    }

    private static class OrCondition
    implements Condition {
        private final Condition[] conditions;

        private OrCondition(final Condition... conditions) {
            this.conditions = conditions;
        }

        @Override
        public boolean allows(final InferenceEngine inferenceEngine, final ActionType payload) {
            for (final Condition c: conditions) {
                if (c.allows(inferenceEngine, payload))
                    return true;
            }
            return false;
        }
    }


    private ConditionJoiner(final boolean disjunction,
                            final Condition identity,
                            final Condition destructor) {
        this.disjunction = disjunction;
        this.identity = identity;
        this.destructor = destructor;
    }

    private static ConditionJoiner conjunction() {
        return new ConditionJoiner(
            false, TrustedCondition.TRUSTED, UntrustedCondition.UNTRUSTED);
    }

    private static ConditionJoiner disjunction() {
        return new ConditionJoiner(
            true, UntrustedCondition.UNTRUSTED, TrustedCondition.TRUSTED);
    }

    private void addTerm(final Condition term) {
        if (term == null)
            throw new NullPointerException();
        if (destroyed || term == identity) {
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

    private void addTerms(final Condition[] lterms) {
        for (final Condition term: lterms) {
            addTerm(term);
        }
    }

    private void addTerms(final List<Condition> lterms) {
        for (final Condition term: lterms) {
            addTerm(term);
        }
    }

    private Condition getCondition() {
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

    public static Condition and(final Condition... conditions) {
        final ConditionJoiner joiner = conjunction();
        joiner.addTerms(conditions);
        return joiner.getCondition();
    }

    public static Condition and(final List<Condition> conditions) {
        final ConditionJoiner joiner = conjunction();
        joiner.addTerms(conditions);
        return joiner.getCondition();
    }

    public static Condition or(final Condition... conditions) {
        final ConditionJoiner joiner = disjunction();
        joiner.addTerms(conditions);
        return joiner.getCondition();
    }

    public static Condition or(final List<Condition> conditions) {
        final ConditionJoiner joiner = disjunction();
        joiner.addTerms(conditions);
        return joiner.getCondition();
    }
}
