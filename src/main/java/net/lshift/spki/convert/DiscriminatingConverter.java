package net.lshift.spki.convert;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

/**
 * Convert to/from a clazz given a list of known subclasses
 * each with a different SExpName
 */
public class DiscriminatingConverter<T>
    extends ConverterImpl<T> {
    private final Map<String, Class<? extends T>> nameMap
        = new HashMap<String, Class<? extends T>>();
    private final Set<Class<? extends T>> classes
        = new HashSet<Class<? extends T>>();

    public DiscriminatingConverter(
        final Class<T> clazz,
        final Class<? extends T>[] classes) {
        super(clazz);
        for (final Class<? extends T> subclass: classes) {
            addClass(subclass);
        }
    }

    public void addClass(final Class<? extends T> subclass) {
        if (!clazz.isAssignableFrom(subclass)) {
            throw new ConvertReflectionException(this, subclass,
                "Class is not a subclass of " + clazz.getCanonicalName());
        }
        final Converter<? extends T> converter = Registry.getConverter(subclass);
        if (!(converter instanceof ListConverter<?>)) {
            throw new ConvertReflectionException(this, subclass,
                    "Converter isn't a list converter");
        }
        final String name = ((ListConverter<? extends T>)converter).getName();
        if (nameMap.containsKey(name)) {
            throw new ConvertReflectionException(this, subclass,
                "Two subclasses share the sexp name " + name);
        }
        nameMap.put(name, subclass);
        this.classes.add(subclass);
    }

    @Override
    public Sexp write(final T o) {
        @SuppressWarnings("unchecked")
        final Class<? extends T> subclass = (Class<? extends T>) o.getClass();
        if (!classes.contains(subclass)) {
            throw new ConvertReflectionException(subclass,
                "Class not known to discriminator");
        }
        return writeUnchecked(subclass, o);
    }

    @Override
    public T read(final Converting c, final Sexp in)
        throws InvalidInputException {
        final byte[] discrim = in.list().getHead().getBytes();
        final String stringDiscrim = ConvertUtils.stringOrNull(discrim);
        final Class<? extends T> subclass = nameMap.get(stringDiscrim);
        if (subclass == null) {
            throw new ConvertException(
                "Unable to find converter: " + stringDiscrim);
        }
        assertMatches(discrim, stringDiscrim);
        return readElement(subclass, c, in);
    }
}
