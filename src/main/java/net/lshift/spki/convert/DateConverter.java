package net.lshift.spki.convert;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Convert between a Date and a SExp
 */
public class DateConverter
        extends StringStepConverter<Date> {

    private static final DateFormat DATE_FORMAT;

    static {
        DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss");
        DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    public static DateFormat getDateFormat() {
        // Astonishingly, DateFormat isn't thread safe.
        return (DateFormat) DATE_FORMAT.clone();
    }

    public DateConverter() {
        super(Date.class);
    }

    @Override
    protected String stepIn(final Date o) {
        return getDateFormat().format(o);
    }

    @Override
    protected Date stepOut(final String o) throws ConvertException {
        try {
            return getDateFormat().parse(o);
        } catch (final java.text.ParseException e) {
            throw new ConvertException(e);
        }
    }
}
