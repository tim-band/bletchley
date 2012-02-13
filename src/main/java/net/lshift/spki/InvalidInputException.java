package net.lshift.spki;

/**
 * Exception thrown when a problem with the input is found: eg doesn't parse
 * at the sexp level, isn't of the form we expect, or the cryptography
 * doesn't check out.
 */
public class InvalidInputException
    extends Exception {
    private static final long serialVersionUID = 1L;

    public InvalidInputException(final String message) {
        super(message);
    }

    public InvalidInputException(final Throwable cause) {
        super(cause);
    }

    public InvalidInputException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
