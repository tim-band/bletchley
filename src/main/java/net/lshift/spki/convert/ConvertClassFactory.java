package net.lshift.spki.convert;

import java.lang.annotation.Annotation;

public class ConvertClassFactory implements ConverterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> Converter<T> converter(final Class<T> c, final Annotation a) {
        final Class<?> t = ((Convert.ConvertClass)a).value();
        try {
            return (Converter<T>) t.newInstance();
        } catch (final InstantiationException e) {
            throw new ConvertReflectionException(c, e);
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(c, e);
        }
    }
}
