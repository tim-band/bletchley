package net.lshift.spki.convert;

import java.lang.annotation.Annotation;

public interface AnnotationHandler<A extends Annotation> {
    void handle(Class<?> clazz, A annotation);
}
