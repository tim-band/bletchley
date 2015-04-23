package net.lshift.spki;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

/**
 * Constants useful in creating and interpreting SPKI S-expressions.
 */
public class Constants {
    private static final DateFormat DATE_FORMAT = getRootFormat();

    private static DateFormat getRootFormat() {
        final SimpleDateFormat res = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss");
        res.setTimeZone(TimeZone.getTimeZone("UTC"));
        return res;
    }

    public static DateFormat getDateFormat() {
        // Astonishingly, DateFormat isn't thread safe.
        return (DateFormat) DATE_FORMAT.clone();
    }
}
