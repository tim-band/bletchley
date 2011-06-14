package net.lshift.spki.convert;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * Convert to/from a superclass given a list of known subclasses
 * each with a different SExpName
 */
public class DiscriminatingConverter<T>
    implements Converter<T> {
    private final Class<T> superclass;
    private final Map<String, Class<? extends T>> nameMap
        = new HashMap<String, Class<? extends T>>();
    private final Set<Class<? extends T>> classes;

    public DiscriminatingConverter(
        final Class<T> superclass,
        final Class<? extends T>[] classes) {
        this.superclass = superclass;
        this.classes  = new HashSet<Class<? extends T>>(
                        Arrays.asList(classes));
        for (final Class<? extends T> clazz: classes) {
            final String name = Registry.getConverter(clazz).getName();
            if (name == null) {
                throw new ConvertReflectionException(this, clazz,
                    "Class has no sexp name");
            }
            nameMap.put(name, clazz);
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
        if (!classes.contains(clazz)) {
            throw new ConvertReflectionException(clazz,
                "Class not known to discriminator");
        }
        out.writeUnchecked(clazz, o);
    }

    @Override
    public T read(final ConvertInputStream in)
        throws InvalidInputException,
            IOException {
        in.nextAssertType(TokenType.OPENPAREN);
        in.nextAssertType(TokenType.ATOM);
        final byte[] discrim = in.atomBytes();
        final Class<? extends T> clazz
            = nameMap.get(ConvertUtils.stringOrNull(discrim));
        if (clazz == null) {
            throw new ConvertException(
                "Unable to find converter: " + discrim);
        }
        in.pushback(discrim);
        in.pushback(TokenType.ATOM);
        in.pushback(TokenType.OPENPAREN);
        return in.read(clazz);
    }

    @Override
    public String getName() {
        // Cannot generate a name for this converter, can be several
        return null;
    }
}
