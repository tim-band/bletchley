package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.ParseException;

/**
 * Interface for an object in the class conversion registry, which can
 * convert between a SExp and an object of type T.
 */
public interface Converter<T> {
    public String getName();

    public void write(ConvertOutputStream out, T o) throws IOException;

    public T read(ConvertInputStream in) throws ParseException, IOException;
}
