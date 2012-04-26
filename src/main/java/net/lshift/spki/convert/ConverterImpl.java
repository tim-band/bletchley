package net.lshift.spki.convert;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

import org.bouncycastle.util.Arrays;

/**
 * Superclass useful for nearly all converters
 */
public abstract class ConverterImpl<T> implements Converter<T> {
    protected final Class<T> clazz;

    public ConverterImpl(Class<T> clazz) {
        this.clazz = clazz;
    }

    @Override
    public Class<T> getResultClass() {
        return clazz;
    }

    protected <U> U readElement(
        final Class<U> elementClass,
        final Converting c,
        final Sexp in)
        throws InvalidInputException {
        return c.read(elementClass, in);
    }

    @SuppressWarnings("unchecked")
    public static Sexp writeUnchecked(final Class<?> clazz, final Object o) {
        if (clazz == Sexp.class) {
            return (Sexp) o;
        }
        return ((Converter<Object>) Registry.getConverter(clazz)).write(o);
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
