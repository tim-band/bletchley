package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.AndCondition.and;

import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;

@Convert.PositionSequence(name="cert", fields={"subject"}, seq="conditions")
public class Cert
    implements SequenceItem {
    public final DigestSha384 subject;
    public final List<Condition> conditions;

    public Cert(DigestSha384 subject, List<Condition> conditions) {
        super();
        this.subject = subject;
        this.conditions = conditions;
    }

    @Override
    public void process(InferenceEngine engine, Condition trust)
        throws InvalidInputException {
        engine.addKeyTrust(subject, and(trust, and(conditions)));
    }
}
