package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;

/**
 * Interface for an object in the class conversion registry, which can
 * convert between a SExp and an object of type T.
 */
public interface Converter<T> {
    public Class<T> getResultClass();

    public String getName();

    public void write(ConvertOutputStream out, T o) throws IOException;

    public T read(ConvertInputStream in)
        throws IOException, InvalidInputException;
}
