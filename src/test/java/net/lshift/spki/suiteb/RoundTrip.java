package net.lshift.spki.suiteb;

import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SExp;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.Convert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RoundTrip
{
    private static final Logger LOG = LoggerFactory.getLogger(RoundTrip.class);

    @SuppressWarnings("unchecked")
    public static <T> T roundTrip(T o)
    {
        try {
            ByteOpenable buf = new ByteOpenable();
            Convert.write(buf, o);
            LOG.info(PrettyPrinter.prettyPrint(Convert.read(SExp.class, buf)));
            // FIXME: I don't understand why a cast is required here.
            return (T) Convert.read(o.getClass(), buf);
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            throw new RuntimeException(e);
        }
    }
}
