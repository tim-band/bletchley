package net.lshift.spki.suiteb;

import java.util.Date;

import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name = "not-after", fields = {"date"})
public class NotAfter implements Condition {
    public final Date date;

    public NotAfter(Date date) {
        super();
        this.date = date;
    }

    @Override
    public boolean allows(InferenceEngine engine, ActionType action) {
        final Date now = engine.getTime();
        if (now == null) {
            throw new IllegalStateException("No time set on InferenceEngine");
        }
        return !now.after(date);
    }
}
