package net.lshift.spki.suiteb;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;

/**
 * SequenceItem container for something the application might act on.
 */
@Convert.ByPosition(name="action", fields={"payload"})
public class Action implements SequenceItem {
    private final ActionType payload;

    public Action(ActionType payload) {
        super();
        this.payload = payload;
    }

    public ActionType getPayload() {
        return payload;
    }
}
