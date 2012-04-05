package net.lshift.spki.convert;

import java.util.Date;

import net.lshift.spki.Constants;

/**
 * Convert between a Date and a SExp
 */
public class DateConverter
    extends StringStepConverter<Date> {
    @Override public Class<Date> getResultClass() { return Date.class; }

    @Override
    protected String stepIn(final Date o) {
        return Constants.getDateFormat().format(o);
    }

    @Override
    protected Date stepOut(final String o) throws ConvertException {
        try {
            return Constants.getDateFormat().parse(o);
        } catch (final java.text.ParseException e) {
            throw new ConvertException(e);
        }
    }
}
