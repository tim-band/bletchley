package net.lshift.spki.suiteb;

import static net.lshift.spki.convert.OpenableUtils.read;
import static net.lshift.spki.convert.OpenableUtils.write;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.convert.ByteOpenable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Put the argument through a serialization/deserialization round trip
 */
public class RoundTrip
{
    private static final Logger LOG = LoggerFactory.getLogger(RoundTrip.class);

    public static <T> T roundTrip(final Class<T> clazz, final T o)
    {
        try {
            final ByteOpenable buf = new ByteOpenable();
            write(clazz, o, buf);
            LOG.info(PrettyPrinter.prettyPrint(buf.read()));
            return read(clazz, buf);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        } catch (final InvalidInputException e) {
            throw new RuntimeException(e);
        }
    }
}
