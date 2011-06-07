package net.lshift.spki.convert;

public class DiscriminatingConverterFactory
    implements ConverterFactory
{
    @SuppressWarnings("unchecked")
    public <T> Converter<T> converter(Class<T> c) {
        return new DiscriminatingConverter<T>(
            (Class<? extends T>[]) c.getAnnotation(Convert.Discriminated.class).value());
    }

}
