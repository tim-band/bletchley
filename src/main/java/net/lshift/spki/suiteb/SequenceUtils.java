package net.lshift.spki.suiteb;

import java.util.Arrays;
import java.util.List;

/**
 * Utilities for working with sequences.
 */
public class SequenceUtils
{
	private SequenceUtils() {
		// This class cannot be instantiated
	}

	public static Action action(ActionType a) {
        return new Action(a);
    }

    public static Sequence sequence(
        final SequenceItem... items
    ) {
        return new Sequence(Arrays.asList(items));
    }

    public static SequenceItem sequenceOrItem(final SequenceItem[] messages) {
        return sequenceOrItem(Arrays.asList(messages));
    }

    public static SequenceItem sequenceOrItem(
        final List<SequenceItem> sequence) {
        if (sequence.size() == 1) {
            return sequence.get(0);
        }
        return new Sequence(sequence);
    }
}
