package net.lshift.spki.convert;

import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

import org.bouncycastle.util.Arrays;

/**
 * Superclass useful for nearly all converters
 */
public abstract class ConverterImpl<T> implements Converter<T> {
    protected final Class<T> clazz;
    private final Map<Class<?>, Converter<?>> extraConverters
        = new HashMap<Class<?>, Converter<?>>();

    public ConverterImpl(final Class<T> clazz) {
        this.clazz = clazz;
    }

    @Override
    public Class<T> getResultClass() {
        return clazz;
    }

    public void addConverter(final Converter<?> converter) {
        extraConverters.put(converter.getResultClass(), converter);
    }

    protected <U> U readElement(
        final Class<U> elementClass,
        final Converting c,
        final Sexp in)
        throws InvalidInputException {
        return c.read(elementClass, extraConverters, in);
    }

    @SuppressWarnings("unchecked")
    public Sexp writeUnchecked(final Class<?> writingClazz, final Object o) {
        if (writingClazz == Sexp.class) {
            return (Sexp) o;
        }
        return ((Converter<Object>) Converting.getConverter(
            extraConverters, writingClazz)).write(o);
    }

    public static void assertMatches(final Sexp atom, final String name)
        throws ConvertException {
        assertMatches(atom.atom().getBytes(), name);
    }

    public static void assertMatches(final byte[] bytes, final String name)
        throws ConvertException {
        if (!Arrays.areEqual(ConvertUtils.bytes(name), bytes)) {
            throw new ConvertException("Unexpected name, expected "
                + name + " got " + ConvertUtils.stringOrNull(bytes));
        }
    }
}
