package net.lshift.spki.convert;

import java.lang.reflect.InvocationTargetException;

/**
 * Create a converter by instantiating the class in the annotation.
 */
public class ConvertClassFactory implements ConverterFactory<Convert.ConvertClass> {
    @SuppressWarnings("unchecked")
    @Override
    public <T> Converter<T> converter(final Class<T> c, final Convert.ConvertClass a) {
        final Class<?> t = a.value();
        try {
            return (Converter<T>) t.getDeclaredConstructor().newInstance();
        } catch (final InstantiationException |
        		IllegalAccessException |
        		NoSuchMethodException |
        		IllegalArgumentException | 
        		InvocationTargetException | 
        		SecurityException e) {
            throw new ConvertReflectionException(c, e);
		}
    }
}
