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
    public void handle(final Class<?> clazz, final RequiresConverter annotation) {
        try {
            Registry.register(annotation.value().newInstance());
        } catch (final InstantiationException e) {
            throw new ConvertReflectionException(clazz, e);
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(clazz, e);
        }
    }
}
