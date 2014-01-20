package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.suiteb.InferenceVariables.setNow;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ReadInfo;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.InferenceEngine;

public class ReadService {
    private static ReadInfo R = getReadInfo();

    static ReadInfo getReadInfo() {
        return ReadInfo.BASE.extend(Service.class);
    }

    private static InferenceEngine newEngine() {
        final InferenceEngine engine = new InferenceEngine(R);
        setNow(engine);
        return engine;
    }

    public static Service readService(final Openable acl, final Openable source)
                    throws IOException, InvalidInputException {
        final InferenceEngine engine = newEngine();
        engine.processTrusted(read(R, acl));
        engine.process(read(R, source));
        return engine.getSoleAction(Service.class);
    }
}
