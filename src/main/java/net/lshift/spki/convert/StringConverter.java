package net.lshift.spki.convert;

import net.lshift.spki.InvalidInputException;

/**
 * Convert between a String and a SExp
 */
public class StringConverter
    extends ByteArrayStepConverter<String> {
    public StringConverter() { super(String.class); }

    @Override
    protected String stepOut(final byte[] s)
        throws InvalidInputException {
        return ConvertUtils.string(s);
    }

    @Override
    protected byte[] stepIn(final String o) {
        return ConvertUtils.bytes(o);
    }
}
