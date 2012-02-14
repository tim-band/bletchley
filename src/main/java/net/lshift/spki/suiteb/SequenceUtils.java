package net.lshift.spki.suiteb;

import java.util.ArrayList;
import java.util.List;


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
