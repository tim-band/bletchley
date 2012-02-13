package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;

/**
 * Converter such that the first two items in the stream are always
 * an open paren and a fixed sexp name. These can be used by
 * DiscriminatingConverter.
 */
public interface ListConverter<T> extends Converter<T> {

    public String getName();

    /**
     * Read only the bits that follow the opening paren and the name
     */
    public T readRest(ConvertInputStream in) throws IOException,
            InvalidInputException;
}
