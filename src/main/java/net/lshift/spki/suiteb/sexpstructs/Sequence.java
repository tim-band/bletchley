package net.lshift.spki.suiteb.sexpstructs;

import java.util.List;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.convert.SequenceConvertable;

/**
 * A list of SequenceItems.  Itself a SequenceItem.
 */
public class Sequence extends SequenceConvertable implements SequenceItem
{
    public final List<SequenceItem> sequence;

    @SExpName("sequence")
    public Sequence(
        @P("sequence") List<SequenceItem> sequence)
    {
        super();
        this.sequence = sequence;
    }
}