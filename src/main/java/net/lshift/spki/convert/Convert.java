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
        Class<? extends ConverterFactory<?>> value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(PositionBeanConverterFactory.class)
    public @interface ByPosition {
        String name();
        String[] fields();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(NameBeanConverterFactory.class)
    public @interface ByName {
        String value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(SequenceConverterFactory.class)
    public @interface SequenceConverted {
        String value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(DiscriminatingConverterFactory.class)
    public @interface Discriminated {
       Class<?> [] value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(ConvertClassFactory.class)
    public @interface ConvertClass {
        // FIXME: why doesn't Class<StepConverter<?,?>> work?
        Class<?> value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.ANNOTATION_TYPE,ElementType.TYPE})
    public @interface HandlerClass {
        Class<? extends AnnotationHandler<?>> value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @HandlerClass(NeedsConverterHandler.class)
    public @interface NeedsConverter {
        Class<? extends Converter<?>> value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @HandlerClass(InstanceOfHandler.class)
    public @interface InstanceOf {
        Class<?> value();
    }
}
