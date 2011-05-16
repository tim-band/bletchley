package net.lshift.spki.convert;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Each field in the constructor of a BeanConverter class should
 * be thusly annotated with the name of the matching bean.
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface P {
    String value();
}
