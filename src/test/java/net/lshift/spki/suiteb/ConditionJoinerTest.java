package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.ConditionJoiner.and;
import static net.lshift.spki.suiteb.ConditionJoiner.or;
import static net.lshift.spki.suiteb.TrustedCondition.TRUSTED;
import static net.lshift.spki.suiteb.UntrustedCondition.UNTRUSTED;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ConditionJoinerTest  {
    private static final Condition[] BOOLEANS
        = new Condition[] {UNTRUSTED, TRUSTED};

    @Test
    public void test() {
        for (final Condition a: BOOLEANS)  {
            for (final Condition b: BOOLEANS) {
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
