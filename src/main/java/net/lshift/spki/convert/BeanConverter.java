package net.lshift.spki.convert;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;

public abstract class BeanConverter<T> implements Converter<T>
{
    protected final String name;
    protected final Constructor<T> constructor;

    @SuppressWarnings("unchecked")
    public BeanConverter(Class<T> clazz)
    {
        ConvertUtils.initialize(clazz);
        for (Constructor<?> c: clazz.getConstructors()) {
            SExpName sname = c.getAnnotation(SExpName.class);
            if (sname != null) {
                name = sname.value();
                constructor = (Constructor<T>) c;
                return;
            }
        }
        throw new ConvertException("No suitably annotated constructor: " +
                        clazz.getCanonicalName());
    }


    protected String getName(Annotation[] annotations)
    {
        for (Annotation a: annotations) {
            if (a instanceof P) {
                return ((P)a).value();
            }
        }
        throw new ConvertException("No P annotation found");
    }
}
