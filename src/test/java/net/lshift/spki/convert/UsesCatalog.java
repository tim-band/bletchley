package net.lshift.spki.convert;

import static net.lshift.spki.convert.openable.OpenableUtils.write;

import java.io.IOException;

import com.google.protobuf.Message;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.InferenceEngine;
import net.lshift.spki.suiteb.SequenceItem;
import net.lshift.spki.suiteb.SequenceItemConverter;

public class UsesCatalog {
    /**
     * Put the argument through a serialization/deserialization round trip
     */
    public <T extends SequenceItem> T roundTrip(
            final Class<T> clazz, 
            final T o, 
            @SuppressWarnings("unchecked") Class<? extends Message> ...actionTypes) {
        return roundTrip(clazz, o, new SequenceItemConverter(actionTypes));
    }

    public <T extends SequenceItem> T roundTrip(
            final Class<T> clazz,
            final T o, 
            SequenceItemConverter parser) {
        try {
            final ByteOpenable buf = new ByteOpenable();
            write(buf, o);
            return parser.parse(buf).require(clazz);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        } catch (final InvalidInputException e) {
            throw new RuntimeException(e);
        }
    }

    public InferenceEngine newEngine(SequenceItemConverter parser) {
        return new InferenceEngine(parser);
    }
}
