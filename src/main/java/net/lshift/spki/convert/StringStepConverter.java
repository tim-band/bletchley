package net.lshift.spki.convert;


public abstract class StringStepConverter<T>
    extends StepConverter<T, String> {

    public StringStepConverter() {
        super();
    }

    @Override
    protected Class<String> getStepClass() { return String.class; }

}
