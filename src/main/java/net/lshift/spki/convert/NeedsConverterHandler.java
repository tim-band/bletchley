package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.NeedsConverter;

public class NeedsConverterHandler
    implements AnnotationHandler<Convert.NeedsConverter>
{
    @Override
    public void handle(Class<?> clazz, NeedsConverter annotation) {
        try {
            Registry.register(annotation.value().newInstance());
        } catch (InstantiationException e) {
            throw new ConvertReflectionException(clazz, e);
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(clazz, e);
        }
    }
}
