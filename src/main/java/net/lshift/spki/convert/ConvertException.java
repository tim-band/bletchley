package net.lshift.spki.convert;

/**
 * Exception thrown if conversion goes wrong.
 *
 * FIXME: should this subclass Exception or RuntimeException?
 */
public class ConvertException
    extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ConvertException(String message) {
        super(message);
    }

    public ConvertException() {
        super();
    }

    public ConvertException(String message, Throwable cause) {
        super(message, cause);
    }

    public ConvertException(Throwable cause) {
        super(cause);
    }
}
