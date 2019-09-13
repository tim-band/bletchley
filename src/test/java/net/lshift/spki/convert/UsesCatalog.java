package net.lshift.spki.convert;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.convert.openable.OpenableUtils.write;

import java.io.IOException;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SimpleMessageProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.SequenceItem;

public class UsesCatalog {
    /**
     * Put the argument through a serialization/deserialization round trip
     */
    public <T extends SequenceItem> T roundTrip(final Class<T> clazz, final T o) {
        try {
            final ByteOpenable buf = new ByteOpenable();
            write(buf, o);
            return read(clazz, buf);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        } catch (final InvalidInputException e) {
            throw new RuntimeException(e);
        }
    }

    public <T extends Message> InferenceEngine<T> newEngine(Class<T> actionType) {
        return new InferenceEngine<T>(actionType, SimpleMessageProto.getDescriptor());
    }
}
