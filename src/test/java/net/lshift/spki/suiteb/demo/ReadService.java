package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;

import java.io.IOException;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.ActionType;
import net.lshift.spki.suiteb.InferenceEngine;

public class ReadService {
    public static Service readService(Openable acl, Openable source)
                    throws IOException, InvalidInputException {
        Registry.getConverter(Service.class);
        InferenceEngine engine = new InferenceEngine();
        engine.setTime();
        engine.processTrusted(read(acl));
        engine.process(read(source));
        List<ActionType> actions = engine.getActions();
        if (actions.size() != 1) {
            throw new RuntimeException(
                "Expected to find exactly one action, found: " + actions.size());
        }
        return (Service) actions.get(0);
    }
}
