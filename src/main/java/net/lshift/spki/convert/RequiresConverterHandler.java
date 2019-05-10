package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.RequiresConverter;

/**
 * When you register a converter, go on to register another converter
 * named here.
 */
public class RequiresConverterHandler
    implements AnnotationHandler<Convert.RequiresConverter>
{
    @Override
    public <U> void handle(
        final Class<U> clazz,
        final Converter<U> converter,
        final RequiresConverter annotation) {
        try {
            ((ConverterImpl<U>)converter).addConverter(annotation.value().newInstance());
        } catch (final InstantiationException|IllegalAccessException e) {
            throw new ConvertReflectionException(clazz, e);
        }
    }
}
