package net.lshift.spki.convert;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
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
    private final Map<String, Class<? extends T>> nameMap = new HashMap<>();
    private final Set<Class<? extends T>> classes = new HashSet<>();

    public DiscriminatingConverter(
        final Class<T> clazz,
        final Class<? extends T>[] classes) {
        super(clazz);
        for (final Class<? extends T> subclass: classes) {
            addClass(subclass);
        }
    }

    private void addClass(final Class<? extends T> subclass) {
        if (!clazz.isAssignableFrom(subclass)) {
            throw new ConvertReflectionException(this, subclass,
                "Class is not a subclass of " + clazz.getCanonicalName());
        }
        final Converter<? extends T> converter = ConverterCache.getConverter(subclass);
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
        if (!classes.contains(subclass) &&
                        getDiscriminatedSuperclass(subclass) != clazz) {
                throw new ConvertReflectionException(this, subclass,
                        "Class is not a member of discriminated union: "
                                        + clazz.getCanonicalName());
        }
        return writeUnchecked(subclass, o);
    }

    @Override
    public T read(final ConverterCatalog r, final Sexp in)
        throws InvalidInputException {
        final byte[] discrim = in.list().getHead().getBytes();
        final String stringDiscrim = ConvertUtils.stringOrNull(discrim);
        final Class<? extends T> subclass = lookupSubclass(r, stringDiscrim);
        assertMatches(discrim, stringDiscrim);
        return readElement(subclass, r, in);
    }

    protected Class<? extends T> lookupSubclass(
        final ConverterCatalog r,
        final String stringDiscrim)
        throws ConvertException {
        Class<? extends T> subclass = nameMap.get(stringDiscrim);
        if (subclass == null) {
            subclass =  r.getExtraDiscrim(clazz, stringDiscrim);
        }
        if (subclass == null) {
            throw new ConvertException(
                "Unable to find converter: " + stringDiscrim);
        }
        return subclass;
    }

    public static Class<?> getDiscriminatedSuperclass(Class<?> clazz) {
        List<Class<?>> answers = new ArrayList<>();
        getDiscriminatedSuperclasses(clazz, answers, clazz);
        if (answers.isEmpty()) {
            throw new ConvertReflectionException(clazz,
                "has no discriminated superclass");
        }
        if (answers.size() > 1) {
            throw new ConvertReflectionException(clazz,
                "is ambiguous: discriminated superclasses "
                                + answers);
        }
        return answers.get(0);
    }

    private static void getDiscriminatedSuperclasses(
        Class<?> clazz,
        List<Class<?>> answers,
        Class<?> sup) {
        if (sup == null)
            return;
        if (sup.getAnnotation(Convert.Discriminated.class) != null) {
            answers.add(sup);
            return;
        }
        getDiscriminatedSuperclasses(clazz, answers,  sup.getSuperclass());
        for (Class<?> supsup: sup.getInterfaces()) {
            getDiscriminatedSuperclasses(clazz, answers, supsup);
        }
    }

    public String toString() {
        return String.format("DiscriminatingConverter<%s>", clazz.getSimpleName()) ;
    }
}
