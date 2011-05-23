package net.lshift.spki.convert;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;

/**
 * Superclass for converters that look for a constructor
 * annotated with the sexp name.
 */
public abstract class BeanConverter<T> implements Converter<T>
{
    protected final Class<T> clazz;
    protected final String name;
    protected final Constructor<T> constructor;

    @SuppressWarnings("unchecked")
    public BeanConverter(Class<T> clazz)
    {
        this.clazz = clazz;
        ConvertUtils.initialize(clazz);
        for (Constructor<?> c: clazz.getConstructors()) {
            SexpName sname = c.getAnnotation(SexpName.class);
            if (sname != null) {
                name = sname.value();
                constructor = (Constructor<T>) c;
                return;
            }
        }
        throw new ConvertException("No suitably annotated constructor: " +
                        clazz.getCanonicalName());
    }

    public String getName()
    {
        return name;
    }

    protected void writeName(ConvertOutputStream out) throws IOException {
        out.atom(name);
    }

    protected String getPAnnotation(Annotation[] annotations)
    {
        for (Annotation a: annotations) {
            if (a instanceof P) {
                return ((P)a).value();
            }
        }
        throw new ConvertException("No P annotation found");
    }
}
