package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.Discriminated;

public class DiscriminatingConverterFactory
    implements ConverterFactory
{
    @SuppressWarnings("unchecked")
    public <T> Converter<T> converter(Class<T> c) {
        final Discriminated annotation
            = c.getAnnotation(Convert.Discriminated.class);
        return new DiscriminatingConverter<T>(
            c, (Class<? extends T>[]) annotation.value());
    }
}
