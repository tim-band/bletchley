package net.lshift.spki.convert;

import net.lshift.spki.InvalidInputException;

/**
 * Exception thrown if conversion goes wrong.
 */
public class ConvertException
    extends InvalidInputException {
    private static final long serialVersionUID = 1L;

    public ConvertException(final String message) {
        super(message);
    }

    public ConvertException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public ConvertException(final Throwable cause) {
        super(cause);
    }
}
