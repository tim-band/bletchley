package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.Discriminated;

public class DiscriminatingConverterFactory
    implements ConverterFactory<Discriminated>
{
    @SuppressWarnings("unchecked")
    public <T> Converter<T> converter(Class<T> c, Discriminated a) {
        return new DiscriminatingConverter<T>(
            c, (Class<? extends T>[]) a.value());
    }
}
