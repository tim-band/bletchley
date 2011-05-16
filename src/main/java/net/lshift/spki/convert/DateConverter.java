package net.lshift.spki.convert;

import java.text.ParseException;
import java.util.Date;

import net.lshift.spki.Constants;
import net.lshift.spki.Create;
import net.lshift.spki.SExp;

/**
 * Convert between a Date and a SExp
 */
public class DateConverter
    implements Converter<Date>
{
    @Override
    public Date fromSexp(SExp sexp)
    {
        try {
            return Constants.DATE_FORMAT.parse(ConvertUtils.toString(sexp));
        } catch (ParseException e) {
            throw new ConvertException(e);
        }
    }

    @Override
    public SExp toSexp(Date o)
    {
        return Create.atom(o);
    }
}
