package net.lshift.spki.convert;

public class ConvertClassFactory implements ConverterFactory<Convert.ConvertClass> {
    @SuppressWarnings("unchecked")
    @Override
    public <T> Converter<T> converter(final Class<T> c, final Convert.ConvertClass a) {
        final Class<?> t = a.value();
        try {
            return (Converter<T>) t.newInstance();
        } catch (final InstantiationException e) {
            throw new ConvertReflectionException(c, e);
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(c, e);
        }
    }
}
