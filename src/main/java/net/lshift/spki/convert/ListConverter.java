package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;

public interface ListConverter<T> extends Converter<T> {

    public String getName();

    /**
     * Read only the bits that follow the opening paren and the name
     */
    public T readRest(ConvertInputStream in) throws IOException,
            InvalidInputException;
}
