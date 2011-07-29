package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

/**
 * Utilities for working with sequences.
 */
public class SequenceUtils
{
    public static Sequence sequence(
        final SequenceItem... items
    ) {
        final List<SequenceItem> sequence = new ArrayList<SequenceItem>();
        for (final SequenceItem item: items) {
            sequence.add(item);
        }
        return new Sequence(sequence);
    }
}
