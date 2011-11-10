package net.lshift.spki.convert;

/**
 * Convenient superclass for converters that go via strings.
 */
public abstract class StringStepConverter<T>
    extends StepConverter<T, String> {

    public StringStepConverter() { super(); }

    @Override protected Class<String> getStepClass() { return String.class; }
}
