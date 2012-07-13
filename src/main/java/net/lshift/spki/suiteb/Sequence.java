package net.lshift.spki.suiteb;

import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert.SequenceConverted;
import net.lshift.spki.convert.SexpBacked;

/**
 * A list of SequenceItems.  Itself a SequenceItem.
 */
@SequenceConverted("sequence")
public class Sequence
    extends SexpBacked
    implements SequenceItem {
    public final List<SequenceItem> sequence;

    public Sequence(final List<SequenceItem> sequence) {
        super();
        this.sequence = sequence;
    }

    @Override
    public void process(final InferenceEngine engine, final Condition trust)
        throws InvalidInputException {
        for (final SequenceItem i: sequence) {
            engine.process(i, trust);
        }
    }
}
