package net.lshift.spki.suiteb;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ConditionJoinerTest  {
    private static final Condition[] BOOLEANS = new Condition[] {
        NeverCondition.NEVER, AlwaysCondition.ALWAYS};

    @Test
    public void test() {
        for (Condition a: BOOLEANS)  {
            for (Condition b: BOOLEANS) {
                assertEquals(
                        a.allows(null, null) || b.allows(null, null),
                        ConditionJoiner.or(a, b).allows(null, null));
                assertEquals(
                        a.allows(null, null) && b.allows(null, null),
                        ConditionJoiner.and(a, b).allows(null, null));
            }
        }
    }

}
