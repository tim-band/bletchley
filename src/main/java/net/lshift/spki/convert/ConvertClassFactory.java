package net.lshift.spki.convert;

import java.lang.annotation.Annotation;

public class ConvertClassFactory implements ConverterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> Converter<T> converter(Class<T> c, Annotation a) {
        Class<?> t = ((Convert.ConvertClass)a).value();
        try {
            return (Converter<T>) t.newInstance();
        } catch (InstantiationException e) {
            throw new ConvertReflectionException(e);
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(e);
        }
    }
}
