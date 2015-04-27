package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.InferenceVariables.NOW;

import java.util.Date;

import net.lshift.spki.convert.Convert;

/**
 * Valid only strictly before the date given -
 * fails on or after that date.
 */
@Convert.ByPosition(name = "invalid-on-or-after", fields = {"date"})
public class InvalidOnOrAfter implements Condition {
    public final Date date;

    public InvalidOnOrAfter(final Date date) {
        super();
        this.date = date;
    }

    @Override
    public boolean allows(final InferenceEngine engine, final ActionType action) {
        return NOW.get(engine).before(date);
    }
}
