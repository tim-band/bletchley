package net.lshift.spki.convert;

/**
 * Exception thrown if reflection fails during conversion.
 */
public class ConvertReflectionException
    extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final Converter<?> converter;
    private final Class<?> type;

    public ConvertReflectionException(Class<?> clazz, String message) {
        super("error converting " + clazz.getCanonicalName() + ": " + message);
        this.converter = null;
        this.type = clazz;
    }

    private static String context(Converter<?> converter, Class<?> type)
    {
        return "error converting " + type.getCanonicalName();
    }

    public ConvertReflectionException(Throwable cause) {
        super(cause);
        this.converter = null;
        this.type = null;
    }

    public ConvertReflectionException(
        Converter<?> converter,
        Class<?> type,
        String message,
        Throwable cause) {
        super(prefix(converter, type, message), cause);
        this.converter = converter;
        this.type = type;
    }

    private static String prefix(
        Converter<?> converter,
        Class<?> type,
        String message)
    {
        return context(converter, type) + ": " + message;
    }

    public ConvertReflectionException(
        Converter<?> converter,
        Class<?> type,
        String message) {
        super(prefix(converter, type, message));
        this.converter = converter;
        this.type = type;
    }


    public ConvertReflectionException(
        Converter<?> converter,
        Class<?> type,
        Throwable cause) {
        super(context(converter, type), cause);
        this.converter = converter;
        this.type = type;
    }

    public Converter<?> getConverter()
    {
        return converter;
    }

    public Class<?> getType()
    {
        return type;
    }


}
