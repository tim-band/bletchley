package net.lshift.spki.convert;

public class StepConverterFactory implements ConverterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> Converter<T> converter(Class<T> c) {
        Class<?> t = c.getAnnotation(Convert.StepConverted.class).value();
        try {
            return (Converter<T>) t.newInstance();
        } catch (InstantiationException e) {
            throw new ConvertReflectionException(e);
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(e);
        }
    }
}
