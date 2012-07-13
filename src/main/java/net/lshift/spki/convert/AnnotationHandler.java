package net.lshift.spki.convert;

import java.lang.annotation.Annotation;

/**
 * Do whatever is needed to handle an annotation of type A
 */
public interface AnnotationHandler<A extends Annotation> {
    <U> void handle(Class<U> clazz, Converter<U> converter, A annotation);
}
