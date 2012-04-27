package net.lshift.spki.convert;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotations to guide the SExp converter.
 */
public class Convert
{
    /**
     * An annotation for annotations - the registry uses this
     * to learn how to interpret an annotation in order to
     * construct a converter for a class
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.ANNOTATION_TYPE})
    public @interface ConverterFactoryClass {
        Class<? extends ConverterFactory<?>> value();
    }

    /**
     * Each field has a specific position in the sexp
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(PositionBeanConverterFactory.class)
    public @interface ByPosition {
        String name();
        String[] fields();
    }

    /**
     * Each field gets a named sub-sexp in the sexp for this object
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(NameBeanConverterFactory.class)
    public @interface ByName {
        String value();
    }

    /**
     * There's only one field, which is a list type; write the name first
     * then convert each element of the list one by one
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(SequenceConverterFactory.class)
    public @interface SequenceConverted {
        String value();
    }

    /**
     * Fields are list types, then they're followed by a sequence.
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(PositionSequenceConverterFactory.class)
    public @interface PositionSequence {
        String name();
        String[] fields();
        String seq();
    }

    /**
     * This is one of several sub-classes, discriminated by the name of the sexp.
     *
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(DiscriminatingConverterFactory.class)
    public @interface Discriminated {
       Class<?> [] value();
    }

    /**
     * The converter should be an instance of this class
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @ConverterFactoryClass(ConvertClassFactory.class)
    public @interface ConvertClass {
        // FIXME: why doesn't Class<StepConverter<?,?>> work?
        Class<? extends Converter<?>> value();
    }

    /**
     * This specifies how to interpret annotations specifying
     * actions that should take place after the converter is registered.
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.ANNOTATION_TYPE})
    public @interface HandlerClass {
        Class<? extends AnnotationHandler<?>> value();
    }

    /**
     * Another converter must be registered for this converter to work
     * - usually a foreign class
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @HandlerClass(RequiresConverterHandler.class)
    public @interface RequiresConverter {
        Class<? extends Converter<?>> value();
    }

    /**
     * This class should be registered after the fact with a
     * DiscriminatingConverter of another class.
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    public @interface InstanceOf {
        Class<?> value();
    }

    /**
     * Mark a field as optional
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.FIELD})
    public @interface Nullable {
        // no fields
    }
}
