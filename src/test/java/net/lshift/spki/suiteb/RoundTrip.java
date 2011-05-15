package net.lshift.spki.suiteb;

import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;
import net.lshift.spki.PrettyPrinter;
import net.lshift.spki.SExp;
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
            SExp sexp = Convert.toSExp(o);
            LOG.info(PrettyPrinter.prettyPrint(sexp));
            byte[] bytes = Marshal.marshal(sexp);
            return (T) Convert.fromBytes(o.getClass(), bytes);
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }
}
