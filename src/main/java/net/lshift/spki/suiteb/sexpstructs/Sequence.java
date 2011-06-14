package net.lshift.spki.suiteb.sexpstructs;

import java.util.List;

import net.lshift.spki.convert.Convert.SequenceConverted;

/**
 * A list of SequenceItems.  Itself a SequenceItem.
 */
@SequenceConverted("sequence")
public class Sequence
    implements SequenceItem {
    public final List<SequenceItem> sequence;

    public Sequence(List<SequenceItem> sequence) {
        super();
        this.sequence = sequence;
    }
}
