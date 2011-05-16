package net.lshift.spki.convert;

/**
 * Exception thrown if reflection fails during conversion.
 */
public class ConvertReflectionException
    extends RuntimeException
{
    private static final long serialVersionUID = 1L;

    public ConvertReflectionException()
    {
        super();
    }

    public ConvertReflectionException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public ConvertReflectionException(String message)
    {
        super(message);
    }

    public ConvertReflectionException(Throwable cause)
    {
        super(cause);
    }
}
