package net.lshift.spki;

/**
 * Exception thrown when efforts to parse an S-expression fail.
 */
public class ParseException extends Exception {
    private static final long serialVersionUID = 1L;

    public ParseException(String message) {
        super(message);
    }

    public ParseException(String message, Throwable t)
    {
        super(message, t);
    }
}
