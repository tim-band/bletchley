package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.InferenceEngine;

public class ReadService {
    public static Service readService(Openable acl, Openable source)
                    throws IOException, InvalidInputException {
        Registry.getConverter(Service.class);
        InferenceEngine engine = new InferenceEngine();
        engine.setTime();
        engine.processTrusted(read(acl));
        engine.process(read(source));
        return (Service) engine.getSoleAction();
    }
}
