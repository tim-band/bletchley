package net.lshift.spki.convert;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Annotation for BeanConvertable constructor giving name for surrounding
 * SExp.
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface SExpName {
    String value();
}
