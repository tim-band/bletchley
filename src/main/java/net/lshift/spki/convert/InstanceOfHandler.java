package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.InstanceOf;

/**
 * Add this class to the list of those handled by a DiscriminatingConverter.
 */
public class InstanceOfHandler implements AnnotationHandler<Convert.InstanceOf> {
    @SuppressWarnings("unchecked")
    @Override
    public <U> void handle(
        final Class<U> clazz,
        final Converter<U> converter,
        final InstanceOf annotation) {
        final Converter<?> dConverter = Registry.getConverter(annotation.value());
        // Horrid hack to allow us to call the method!
        ((DiscriminatingConverter<Object>)dConverter).addClass(clazz);
    }
}
