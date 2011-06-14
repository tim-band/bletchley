package net.lshift.spki.convert;

import java.lang.annotation.Annotation;

/**
 * Converter factory. Represents a category of converters.
 * @see Convert#ConverterFactoryClass
 */
public interface ConverterFactory<A extends Annotation>
{
    /**
     * Return a converter for for the given class
     * @throws IllegalArgumentException if the class is
     * not compatible with the converter. Eg. a required annotation
     * is missing.
     */
    public <T> Converter<T> converter(Class<T> c, A a);
}
