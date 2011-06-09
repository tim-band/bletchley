package net.lshift.spki.convert;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
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
        final Class<T> superclass,
        final Class<? extends T>[] classes) {
        this.superclass = superclass;
        for (final Class<? extends T> clazz: classes) {
            final Converter<? extends T> converter
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
    public void write(final ConvertOutputStream out, final T o)
        throws IOException {
        final Class<? extends T> clazz = (Class<? extends T>) o.getClass();
        final Converter<? extends T> converter = classMap.get(clazz);
        if (converter == null) {
            throw new ConvertReflectionException(clazz,
                "Class not known to discriminator");
        }
        ((Converter<T>)converter).write(out, o);
    }

    @Override
    public T read(final ConvertInputStream in)
        throws InvalidInputException,
            IOException {
        in.nextAssertType(TokenType.OPENPAREN);
        in.nextAssertType(TokenType.ATOM);
        final byte[] discrim = in.atomBytes();
        final Converter<? extends T> converter
            = nameMap.get(ConvertUtils.stringOrNull(discrim));
        if (converter == null) {
            throw new ConvertException(
                "Unable to find converter: " + discrim);
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
