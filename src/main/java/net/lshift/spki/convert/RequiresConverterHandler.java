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
    public void handle(Class<?> clazz, RequiresConverter annotation) {
        try {
            Registry.register(annotation.value().newInstance());
        } catch (InstantiationException e) {
            throw new ConvertReflectionException(clazz, e);
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(clazz, e);
        }
    }
}
