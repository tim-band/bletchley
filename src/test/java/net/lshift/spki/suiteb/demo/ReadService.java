package net.lshift.spki.suiteb.demo;

import java.io.IOException;
import java.util.List;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;
import net.lshift.spki.suiteb.ActionType;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.SequenceItem;

public class ReadService {
    public static Service readService(Openable source)
                    throws IOException, InvalidInputException {
        Registry.getConverter(Service.class);
        InferenceEngine engine = new InferenceEngine();
        engine.processTrusted(
            OpenableUtils.read(SequenceItem.class, source));
        List<ActionType> actions = engine.getActions();
        if (actions.size() != 1) {
            throw new RuntimeException(
                "Expected to find exactly one action, found: " + actions.size());
        }
        return (Service) actions.get(0);
    }
}
