package net.lshift.spki.suiteb.sexpstructs;

import java.util.List;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SexpName;
import net.lshift.spki.convert.Convert.SequenceConverted;

/**
 * A list of SequenceItems.  Itself a SequenceItem.
 */
@SequenceConverted
public class Sequence
    implements SequenceItem {
    public final List<SequenceItem> sequence;

    @SexpName("sequence")
    public Sequence(@P("sequence") List<SequenceItem> sequence) {
        super();
        this.sequence = sequence;
    }
}
