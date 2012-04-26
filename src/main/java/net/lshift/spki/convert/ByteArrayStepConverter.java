package net.lshift.spki.convert;

/**
 * Convenient superclass for converters that go via byte arrays.
 */
public abstract class ByteArrayStepConverter<T>
    extends StepConverter<T, byte[]> {

    public ByteArrayStepConverter(Class<T> clazz) {
        super(clazz);
    }

    @Override protected Class<byte[]> getStepClass() { return byte[].class; }
}
