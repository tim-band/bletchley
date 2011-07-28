package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.Discriminated;

public class DiscriminatingConverterFactory
    implements ConverterFactory<Discriminated>
{
    @Override
    @SuppressWarnings("unchecked")
    public <T> Converter<T> converter(final Class<T> c, final Discriminated a) {
        return new DiscriminatingConverter<T>(
            c, (Class<? extends T>[]) a.value());
    }
}
