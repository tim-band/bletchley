package net.lshift.spki.convert;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.Constants;
import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * Convert to/from a superclass given a list of known subclasses
 * each with a different SExpName
 */
public class DiscriminatingConverter<T> implements Converter<T>
{
    private final Map<String, Converter<? extends T>> nameMap
        = new HashMap<String, Converter<? extends T>>();
    private final HashMap<Class<? extends T>, Converter<? extends T>> classMap
        = new HashMap<Class<? extends T>, Converter<? extends T>>();

    public DiscriminatingConverter(Class<? extends T>... classes)
    {
        for (Class<? extends T> clazz: classes) {
            Converter<? extends T> converter
                = Convert.REGISTRY.getConverter(clazz);
            classMap.put(clazz, converter);
            nameMap.put(
                ((BeanConverter<? extends T>) converter).getName(),
                converter);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public void write(ConvertOutputStream out, T o)
        throws IOException
    {
        final Converter<? extends T> converter = classMap.get(o.getClass());
        if (converter == null) {
            throw new ConvertException("Don't know how to convert from: "
                + o.getClass().getCanonicalName());
        }
        ((Converter<T>)converter).write(out, o);
    }

    @Override
    public T read(ConvertInputStream in)
        throws ParseException,
            IOException
    {
        in.nextAssertType(TokenType.OPENPAREN);
        in.nextAssertType(TokenType.ATOM);
        byte[] discrim = in.atomBytes();
        Converter<? extends T> converter
            = nameMap.get(new String(discrim, Constants.UTF8));
        in.pushback(discrim);
        in.pushback(TokenType.ATOM);
        in.pushback(TokenType.OPENPAREN);
        return converter.read(in);
    }
}
