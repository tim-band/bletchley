package net.lshift.spki.convert;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

/**
 * Convert to/from a superclass given a list of known subclasses
 * each with a different SExpName
 */
public class DiscriminatingConverter<T>
    implements Converter<T> {
    private final Class<T> superclass;
    private final Map<String, Class<? extends T>> nameMap
        = new HashMap<String, Class<? extends T>>();
    private final Set<Class<? extends T>> classes
        = new HashSet<Class<? extends T>>();

    public DiscriminatingConverter(
        final Class<T> superclass,
        final Class<? extends T>[] classes) {
        this.superclass = superclass;
        for (final Class<? extends T> clazz: classes) {
            addClass(clazz);
        }
    }

    public void addClass(final Class<? extends T> clazz) {
        if (!superclass.isAssignableFrom(clazz)) {
            throw new ConvertReflectionException(this, clazz,
                "Class is not a subclass of " + superclass.getCanonicalName());
        }
        final Converter<? extends T> converter = Registry.getConverter(clazz);
        if (!(converter instanceof ListConverter<?>)) {
            throw new ConvertReflectionException(this, clazz,
                    "Converter isn't a list converter");
        }
        final String name = ((ListConverter<? extends T>)converter).getName();
        if (nameMap.containsKey(name)) {
            throw new ConvertReflectionException(this, clazz,
                "Two subclasses share the sexp name " + name);
        }
        nameMap.put(name, clazz);
        this.classes.add(clazz);
    }

    @Override
    public Class<T> getResultClass() {
        return superclass;
    }

    @Override
    public Sexp write(final Converting c, final T o) {
        @SuppressWarnings("unchecked")
        final Class<? extends T> clazz = (Class<? extends T>) o.getClass();
        if (!classes.contains(clazz)) {
            throw new ConvertReflectionException(clazz,
                "Class not known to discriminator");
        }
        return c.writeUnchecked(clazz, o);
    }

    @Override
    public T read(final Converting c, final Sexp in)
        throws InvalidInputException {
        final byte[] discrim = in.list().getHead().getBytes();
        final String stringDiscrim = ConvertUtils.stringOrNull(discrim);
        final Class<? extends T> clazz = nameMap.get(stringDiscrim);
        if (clazz == null) {
            throw new ConvertException(
                "Unable to find converter: " + stringDiscrim);
        }
        BeanConverter.assertMatches(discrim, stringDiscrim);
        return c.read(clazz, in);
    }
}
