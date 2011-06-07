package net.lshift.spki.convert;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

public class Convert
{
    @Target({ElementType.ANNOTATION_TYPE,ElementType.TYPE})
    public @interface ConverterFactoryClass {
        @SuppressWarnings("rawtypes")
        Class<? extends ConverterFactory> value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(PositionBeanConverterFactory.class)
    public @interface ByPosition { }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(NameBeanConverterFactory.class)
    public @interface ByName { }


    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(DiscriminatingConverterFactory.class)
    public @interface Discriminated {
       Class<?> [] value();
    }
}
