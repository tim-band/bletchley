package net.lshift.spki.convert;

/**
 * Exception thrown if reflection fails during conversion.
 */
public class ConvertReflectionException
    extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ConvertReflectionException(final Class<?> clazz, final String message) {
        super("error converting " + clazz.getCanonicalName() + ": " + message);
    }

    public ConvertReflectionException(final Class<?> clazz, final Throwable t) {
        super("error converting " + clazz.getCanonicalName(), t);
    }

    public ConvertReflectionException(
        final Class<?> clazz,
        final String message,
        final Throwable t) {
        super("error converting " + clazz.getCanonicalName() + ": " + message, t);
    }

    public ConvertReflectionException(ReflectiveOperationException e) {
		super("Error during conversion", e);
	}

}
