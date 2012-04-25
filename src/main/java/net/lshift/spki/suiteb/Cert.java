package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.ConditionJoiner.and;

import java.util.Arrays;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;

@Convert.PositionSequence(name="cert", fields={"subject"}, seq="conditions")
public class Cert
    extends SexpBacked
    implements SequenceItem {
    public final DigestSha384 subject;
    public final List<Condition> conditions;

    public Cert(final DigestSha384 subject, final List<Condition> conditions) {
        super();
        this.subject = subject;
        this.conditions = conditions;
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        engine.addKeyTrust(subject, and(trust, and(conditions)));
    }

    public static Cert cert(
        final DigestSha384 subject,
        final Condition... conditions) {
        return new Cert(subject, Arrays.asList(conditions));
    }

    public static Cert cert(
        final PublicSigningKey subject,
        final Condition... conditions) {
        return cert(subject.getKeyId(), conditions);
    }

    public static Cert cert(
        final PrivateSigningKey subject,
        final Condition... conditions) {
        return cert(subject.getPublicKey(), conditions);
    }
}
