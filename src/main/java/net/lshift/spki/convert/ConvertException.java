package net.lshift.spki.convert;

/**
 * Exception thrown if conversion goes wrong.
 *
 * FIXME: should this subclass Exception or RuntimeException?
 */
public class ConvertException
    extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ConvertException(final String message) {
        super(message);
    }

    public ConvertException() {
        super();
    }

    public ConvertException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public ConvertException(final Throwable cause) {
        super(cause);
    }
}
