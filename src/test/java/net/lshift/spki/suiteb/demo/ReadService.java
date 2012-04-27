package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.suiteb.InferenceVariables.NOW;

import java.io.IOException;
import java.util.Date;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Converting;
import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.InferenceEngine;

public class ReadService {
    private static Converting C = getConverting();

    static Converting getConverting() {
        Converting c = new Converting();
        c.register(Service.class);
        return c;
    }

    private static InferenceEngine newEngine() {
        return new InferenceEngine(C);
    }

    public static Service readService(final Openable acl, final Openable source)
                    throws IOException, InvalidInputException {
        Registry.getConverter(Service.class);
        final InferenceEngine engine = newEngine();
        NOW.set(engine, new Date());
        engine.processTrusted(read(C, acl));
        engine.process(read(C, source));
        return (Service) engine.getSoleAction();
    }
}
