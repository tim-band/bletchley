package net.lshift.spki.suiteb;

import java.util.Date;

import com.google.protobuf.Message;

public class InferenceVariables {
    private InferenceVariables() {
        // This class cannot be instantiated
    }

    public static final InferenceVariable<Date> NOW = new InferenceVariable<>(Date.class, "now");

    public static void setNow(final InferenceEngine<? extends Message> engine) {
        NOW.set(engine, new Date());
    }
}
