package net.lshift.spki.suiteb.sexpstructs;

import java.util.List;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SexpName;
import net.lshift.spki.convert.SequenceConvertible;

/**
 * A list of SequenceItems.  Itself a SequenceItem.
 */
public class Sequence extends SequenceConvertible implements SequenceItem
{
    public final List<SequenceItem> sequence;

    @SexpName("sequence")
    public Sequence(
        @P("sequence") List<SequenceItem> sequence)
    {
        super();
        this.sequence = sequence;
    }
}
