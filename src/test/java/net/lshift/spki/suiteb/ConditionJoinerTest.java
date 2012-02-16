package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.AlwaysCondition.ALWAYS;
import static net.lshift.spki.suiteb.ConditionJoiner.and;
import static net.lshift.spki.suiteb.ConditionJoiner.or;
import static net.lshift.spki.suiteb.NeverCondition.NEVER;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ConditionJoinerTest  {
    private static final Condition[] BOOLEANS
        = new Condition[] {NEVER, ALWAYS};

    @Test
    public void test() {
        for (Condition a: BOOLEANS)  {
            for (Condition b: BOOLEANS) {
                assertEquals(
                        a.allows(null, null) || b.allows(null, null),
                        or(a, b).allows(null, null));
                assertEquals(
                        a.allows(null, null) && b.allows(null, null),
                        and(a, b).allows(null, null));
            }
        }
    }
}
