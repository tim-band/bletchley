package net.lshift.spki.convert;

import java.lang.reflect.Field;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

public class Converting {
    private static final Field SEXP_FIELD = getSexpField();

    private static Field getSexpField() {
        try {
            final Field res = SexpBacked.class.getDeclaredField("sexp");
            res.setAccessible(true);
            return res;
        } catch (final NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public <T> T read(final Class<T> clazz, final Sexp sexp) throws InvalidInputException {
        // FIXME: this sure is ugly!
        if (clazz == Sexp.class) {
            return (T) sexp;
        }
        final T res = Registry.getConverter(clazz).read(this, sexp);
        // FIXME: so is this!
        // FIXME: use the dynamic class here?
        if (SexpBacked.class.isAssignableFrom(clazz)) {
            try {
                SEXP_FIELD.set(res, sexp);
            } catch (final IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
        return res;
    }
}
