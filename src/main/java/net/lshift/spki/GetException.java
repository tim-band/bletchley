package net.lshift.spki;

/**
 * Exception thrown by static methods in Get if some assumption is false.
 * Note that they can also throw eg ClassCastException if something is wrong.
 */
public class GetException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public GetException(String message) {
        super(message);
        // TODO Auto-generated constructor stub
    }
}
