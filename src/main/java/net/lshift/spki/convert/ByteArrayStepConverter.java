package net.lshift.spki.convert;

/**
 * Convenient superclass for converters that go via byte arrays.
 */
public abstract class ByteArrayStepConverter<T>
    extends StepConverter<T, byte[]> {

    public ByteArrayStepConverter() { super(); }

    @Override protected Class<byte[]> getStepClass() { return byte[].class; }
}
