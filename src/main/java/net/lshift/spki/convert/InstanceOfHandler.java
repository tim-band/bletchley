package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.InstanceOf;

/**
 * Add this class to the list of those handled by a DiscriminatingConverter.
 */
public class InstanceOfHandler implements AnnotationHandler<Convert.InstanceOf> {
    @SuppressWarnings("unchecked")
    @Override
    public void handle(Class<?> clazz, InstanceOf annotation) {
        Converter<?> converter = Registry.getConverter(annotation.value());
        // Horrid hack to allow us to call the method!
        ((DiscriminatingConverter<Object>)converter).addClass(clazz);
    }
}
