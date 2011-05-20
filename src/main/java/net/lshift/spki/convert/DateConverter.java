package net.lshift.spki.convert;

import java.text.ParseException;
import java.util.Date;

import net.lshift.spki.Constants;
import net.lshift.spki.Create;
import net.lshift.spki.Sexp;

/**
 * Convert between a Date and a SExp
 */
public class DateConverter
    implements Converter<Date>
{
    @Override
    public Date fromSexp(Sexp sexp)
    {
        try {
            return Constants.DATE_FORMAT.parse(ConvertUtils.toString(sexp));
        } catch (ParseException e) {
            throw new ConvertException(e);
        }
    }

    @Override
    public Sexp toSexp(Date o)
    {
        return Create.atom(Constants.DATE_FORMAT.format(o));
    }
}
