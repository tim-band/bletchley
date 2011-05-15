package net.lshift.spki.convert;

import net.lshift.spki.SExp;

public interface Converter<T>
{
    public SExp toSexp(T o);

    public T fromSexp(SExp sexp);
}
