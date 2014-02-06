package net.lshift.spki.convert;

/**
 * Exception thrown if reflection fails during conversion.
 */
public class ConvertReflectionException
    extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final Class<?> type;
    private final Converter<?> converter;

    public ConvertReflectionException(final Class<?> clazz, final String message) {
        super("error converting " + clazz.getCanonicalName() + ": " + message);
        this.converter = null;
        this.type = clazz;
    }

    public ConvertReflectionException(final Class<?> clazz, final Throwable t) {
        super("error converting " + clazz.getCanonicalName(), t);
        this.converter = null;
        this.type = clazz;
    }

    public ConvertReflectionException(
        final Class<?> clazz,
        final String message,
        final Throwable t) {
        super("error converting " + clazz.getCanonicalName() + ": " + message, t);
        this.converter = null;
        this.type = clazz;
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
        this.converter = converter;
        this.type = type;
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
        this.converter = converter;
        this.type = type;
    }


    public ConvertReflectionException(
        final Converter<?> converter,
        final Class<?> type,
        final Throwable cause) {
        super(context(converter, type), cause);
        this.converter = converter;
        this.type = type;
    }

    public Converter<?> getConverter() {
        return converter;
    }

    public Class<?> getType() {
        return type;
    }
}
