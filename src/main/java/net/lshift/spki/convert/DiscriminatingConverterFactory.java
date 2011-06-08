package net.lshift.spki.convert;

import java.lang.annotation.Annotation;

import net.lshift.spki.convert.Convert.Discriminated;

public class DiscriminatingConverterFactory
    implements ConverterFactory
{
    @SuppressWarnings("unchecked")
    public <T> Converter<T> converter(final Class<T> c, final Annotation a) {
        return new DiscriminatingConverter<T>(
            c, (Class<? extends T>[]) ((Discriminated)a).value());
    }
}
