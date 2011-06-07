package net.lshift.spki.convert;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

public class Convert
{
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.ANNOTATION_TYPE,ElementType.TYPE})
    public @interface ConverterFactoryClass {
        Class<? extends ConverterFactory> value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(PositionBeanConverterFactory.class)
    public @interface ByPosition { /* no arguments */}

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(NameBeanConverterFactory.class)
    public @interface ByName { /* no arguments */ }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(SequenceConverterFactory.class)
    public @interface SequenceConverted { /* no arguments */ }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(DiscriminatingConverterFactory.class)
    public @interface Discriminated {
       Class<?> [] value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(StepConverterFactory.class)
    public @interface StepConverted {
        // FIXME: why doesn't Class<StepConverter<?,?>> work?
        Class<?> value();
    }
}
