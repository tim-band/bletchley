package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.ConditionJoiner.and;

import java.util.Arrays;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;

@Convert.PositionSequence(name="limit", fields={"subject"}, seq="conditions")
public class Limit
    extends SexpBacked
    implements SequenceItem {
    public final SequenceItem subject;
    public final List<Condition> conditions;

    public Limit(final SequenceItem subject, final List<Condition> conditions) {
        super();
        this.subject = subject;
        this.conditions = conditions;
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        engine.process(subject, and(trust, and(conditions)));
    }

    public static Limit limit(
        final SequenceItem subject,
        final Condition... conditions) {
        return new Limit(subject, Arrays.asList(conditions));
    }
}
