package net.lshift.spki.convert;

import java.util.Set;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.schema.ConverterDeclaration;
import net.lshift.spki.sexpform.Sexp;

/**
 * Interface for an object in the class conversion registry, which can
 * convert between a SExp and an object of type T.
 */
public interface Converter<T> {
    public Class<T> getResultClass();

    public Sexp write(T o);

    public T read(ConverterCatalog r, Sexp in)
        throws InvalidInputException;

    public ConverterDeclaration declaration();

    public Set<Class<?>> references();
}
