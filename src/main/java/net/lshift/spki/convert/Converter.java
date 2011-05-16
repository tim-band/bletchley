package net.lshift.spki.convert;

import net.lshift.spki.SExp;

/**
 * Interface for an object in the class conversion registry, which can
 * convert between a SExp and an object of type T.
 */
public interface Converter<T>
{
    public SExp toSexp(T o);

    public T fromSexp(SExp sexp);
}
