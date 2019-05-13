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

    private static String context(
        final Converter<?> converter,
        final Class<?> type)    {
        return "error converting " + type.getCanonicalName();
    }

    public ConvertReflectionException(
        final Converter<?> converter,
        final Class<?> type,
        final String message,
        final Throwable cause) {
        super(prefix(converter, type, message), cause);
    }

    private static String prefix(
        final Converter<?> converter,
        final Class<?> type,
        final String message)
    {
        return context(converter, type) + ": " + message;
    }

    public ConvertReflectionException(
        final Converter<?> converter,
        final Class<?> type,
        final String message) {
        super(prefix(converter, type, message));
    }


    public ConvertReflectionException(
        final Converter<?> converter,
        final Class<?> type,
        final Throwable cause) {
        super(context(converter, type), cause);
    }

    public ConvertReflectionException(ReflectiveOperationException e) {
		super("Error during conversion", e);
	}

}
