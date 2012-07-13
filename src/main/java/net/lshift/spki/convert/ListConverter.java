package net.lshift.spki.convert;

/**
 * Converter such that the first two items in the stream are always
 * an open paren and a fixed sexp name. These can be used by
 * DiscriminatingConverter.
 */
public interface ListConverter<T> extends Converter<T> {
    public String getName();
}
