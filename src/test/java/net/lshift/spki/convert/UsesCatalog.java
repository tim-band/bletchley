package net.lshift.spki.convert;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.convert.openable.OpenableUtils.write;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.InferenceEngine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class UsesCatalog {
    private static final Logger LOG = LoggerFactory.getLogger(UsesCatalog.class);

    protected ConverterCatalog getReadInfo() {
        return ConverterCatalog.BASE;
    }

    /**
     * Put the argument through a serialization/deserialization round trip
     */

    public <T extends Writeable> T roundTrip(
        final Class<T> clazz, final T o)
    {
        try {
            final ByteOpenable buf = new ByteOpenable();
            write(buf, o);
            LOG.info("\n{}", PrettyPrinter.prettyPrint(buf.read()));
            return read(getReadInfo(), clazz, buf);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        } catch (final InvalidInputException e) {
            throw new RuntimeException(e);
        }
    }

    public InferenceEngine newEngine() {
        return new InferenceEngine(getReadInfo());
    }
}
