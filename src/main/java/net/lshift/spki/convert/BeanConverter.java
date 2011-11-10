package net.lshift.spki.convert;

import java.io.IOException;

/**
 * Superclass for converters that look for a constructor
 * annotated with the sexp name.
 */
public abstract class BeanConverter<T>
    implements Converter<T> {
    protected final Class<T> clazz;
    protected final String name;

    public BeanConverter(final Class<T> clazz, final String name) {
        this.clazz = clazz;
        this.name = name;
    }

    @Override
    public Class<T> getResultClass() {
        return clazz;
    }

    @Override
    public String getName() {
        return name;
    }

    protected void writeName(final ConvertOutputStream out)
        throws IOException {
        out.atom(name);
    }
}
