package net.lshift.spki.convert;

public class ConvertClassFactory implements ConverterFactory<Convert.ConvertClass> {
    @SuppressWarnings("unchecked")
    @Override
    public <T> Converter<T> converter(Class<T> c, Convert.ConvertClass a) {
        Class<?> t = a.value();
        try {
            return (Converter<T>) t.newInstance();
        } catch (InstantiationException e) {
            throw new ConvertReflectionException(e);
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(e);
        }
    }
}
