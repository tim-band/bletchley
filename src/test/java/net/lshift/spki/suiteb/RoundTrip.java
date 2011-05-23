package net.lshift.spki.suiteb;

import static net.lshift.spki.convert.OpenableUtils.read;
import static net.lshift.spki.convert.OpenableUtils.write;

import java.io.IOException;

import net.lshift.spki.ParseException;
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

    public static <T> T roundTrip(Class<T> clazz, T o)
    {
        try {
            ByteOpenable buf = new ByteOpenable();
            write(buf, clazz, o);
            LOG.info(PrettyPrinter.prettyPrint(buf.read()));
            return read(clazz, buf);
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
