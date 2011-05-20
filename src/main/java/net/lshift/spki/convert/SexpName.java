package net.lshift.spki.convert;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Annotation for BeanConvertible constructor giving name for surrounding
 * SExp.
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface SexpName {
    String value();
}
