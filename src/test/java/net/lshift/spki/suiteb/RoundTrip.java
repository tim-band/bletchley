package net.lshift.spki.suiteb;

import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SExp;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.Convert;

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
            Convert.write(buf, clazz, o);
            LOG.info(PrettyPrinter.prettyPrint(Convert.read(SExp.class, buf)));
            return Convert.read(clazz, buf);
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
