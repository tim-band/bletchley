package net.lshift.spki.convert;

import java.util.Date;

import net.lshift.spki.Constants;

/**
 * Convert between a Date and a SExp
 */
public class DateConverter
    extends StringStepConverter<Date> {
    public DateConverter() { super(Date.class); }

    @Override
    protected String stepIn(final Date o) {
        return Constants.DATE_FORMAT.format(o);
    }

    @Override
    protected Date stepOut(final String o) throws ConvertException {
        try {
            return Constants.DATE_FORMAT.parse(o);
        } catch (final java.text.ParseException e) {
            throw new ConvertException(e);
        }
    }
}
