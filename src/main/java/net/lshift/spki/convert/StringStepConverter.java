package net.lshift.spki.convert;

/**
 * Convenient superclass for converters that go via strings.
 */
public abstract class StringStepConverter<T>
    extends StepConverter<T, String> {

    public StringStepConverter(Class<T> clazz) {
        super(clazz);
    }

    @Override protected Class<String> getStepClass() { return String.class; }
}
