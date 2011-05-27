package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

public class SequenceUtils
{
    public static Sequence sequence(
        SequenceItem... items
    ) {
        List<SequenceItem> sequence = new ArrayList<SequenceItem>();
        for (SequenceItem item: items) {
            sequence.add(item);
        }
        return new Sequence(sequence);
    }
}
