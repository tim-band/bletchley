package net.lshift.spki.convert;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * Convert to/from a superclass given a list of known subclasses
 * each with a different SExpName
 */
public class DiscriminatingConverter<T>
    implements Converter<T> {
    private final Class<T> superclass;
    private final Map<String, Converter<? extends T>> nameMap
        = new HashMap<String, Converter<? extends T>>();
    private final HashMap<Class<? extends T>, Converter<? extends T>> classMap
        = new HashMap<Class<? extends T>, Converter<? extends T>>();


    public DiscriminatingConverter(
        Class<T> superclass,
        Class<? extends T>[] classes) {
        this.superclass = superclass;
        for (Class<? extends T> clazz: classes) {
            Converter<? extends T> converter
                = Registry.REGISTRY.getConverter(clazz);
            classMap.put(clazz, converter);
            final String name = converter.getName();
            if (name == null) {
                throw new ConvertReflectionException(this, clazz,
                    "Class has no sexp name");
            }
            nameMap.put(name, converter);
        }
    }

    @Override
    public Class<T> getResultClass() {
        return superclass;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void write(ConvertOutputStream out, T o)
        throws IOException {
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
            IOException {
        in.nextAssertType(TokenType.OPENPAREN);
        in.nextAssertType(TokenType.ATOM);
        byte[] discrim = in.atomBytes();
        Converter<? extends T> converter
            = nameMap.get(ConvertUtils.stringOrNull(discrim));
        if (converter == null) {
            throw new ParseException("Unable to find converter");
        }
        in.pushback(discrim);
        in.pushback(TokenType.ATOM);
        in.pushback(TokenType.OPENPAREN);
        return converter.read(in);
    }

    @Override
    public String getName() {
        // Cannot generate a name for this converter, can be several
        return null;
    }
}
