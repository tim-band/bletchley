package net.lshift.spki.convert;


public abstract class ByteArrayStepConverter<T>
    extends StepConverter<T, byte[]> {

    public ByteArrayStepConverter() {
        super();
    }

    @Override
    public String getName() { return null; }

    @Override
    protected Class<byte[]> getStepClass() {
        return byte[].class;
    }
}
