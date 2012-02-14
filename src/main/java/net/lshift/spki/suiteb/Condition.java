package net.lshift.spki.suiteb;

import net.lshift.spki.convert.Convert;

@Convert.Discriminated({
    NotAfter.class
})
public interface Condition {
    boolean allows(InferenceEngine inferenceEngine, ActionType payload);
}
