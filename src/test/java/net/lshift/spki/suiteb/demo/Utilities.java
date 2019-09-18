package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.InferenceVariables.setNow;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;

import java.io.IOException;

import net.lshift.bletchley.suiteb.demo.DemoProto.Service;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.SequenceItem;
import net.lshift.spki.suiteb.SequenceItemConverter;

public class Utilities {

    public static SequenceItem read(Openable message) 
            throws IOException, InvalidInputException {
        return new SequenceItemConverter(Service.class).parse(message);
    }

    public static InferenceEngine newEngine() {
        final InferenceEngine engine = new InferenceEngine(Service.class);
        setNow(engine);
        return engine;
    }

    public static Openable emptyByteOpenable() {
        try {
            return asOpenable(sequence());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Openable asOpenable(SequenceItem sequence) throws IOException {
        final ByteOpenable target = new ByteOpenable();
        write(target, sequence);
        return target;
    }
}
