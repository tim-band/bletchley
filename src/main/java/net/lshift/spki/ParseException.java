package net.lshift.spki;

/**
 * Exception thrown when efforts to parse an S-expression fail.
 */
public class ParseException extends InvalidInputException {
    private static final long serialVersionUID = 1L;

    public ParseException(final String message) {
        super(message);
    }

    public ParseException(final String message, final Throwable t)
    {
        super(message, t);
    }
}
