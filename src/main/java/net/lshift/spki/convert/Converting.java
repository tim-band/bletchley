package net.lshift.spki.convert;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

public class Converting {
    public static <T extends Writeable> Sexp write(final Class<T> clazz, final T o) {
        if (clazz == Sexp.class) {
            return (Sexp) o;
        }
        return Registry.getConverter(clazz).write(o);
    }

    @SuppressWarnings("unchecked")
    public static Sexp writeUnchecked(final Class<?> clazz, final Object o) {
        if (clazz == Sexp.class) {
            return (Sexp) o;
        }
        return ((Converter<Object>) Registry.getConverter(clazz)).write(o);
    }

    @SuppressWarnings("unchecked")
    public <T> T read(final Class<T> clazz, final Sexp sexp) throws InvalidInputException {
        // FIXME: this sure is ugly!
        if (clazz == Sexp.class) {
            return (T) sexp;
        }
        return Registry.getConverter(clazz).read(this, sexp);
    }
}
