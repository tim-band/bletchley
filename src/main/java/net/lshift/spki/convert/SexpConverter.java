package net.lshift.spki.convert;

import java.util.Collections;
import java.util.Set;

import net.lshift.spki.schema.ConverterDeclaration;
import net.lshift.spki.schema.ExprType;
import net.lshift.spki.sexpform.Sexp;

public class SexpConverter
    implements Converter<Sexp>
{
    @Override
    public Class<Sexp> getResultClass() { return Sexp.class; }

    @Override
    public Sexp write(Sexp o) { return o; }

    @Override
    public Sexp read(ConverterCatalog r, Sexp in) { return in; }

    @Override
    public ConverterDeclaration declaration() {
        return new ExprType();
    }

    @Override
    public Set<Class<?>> references() {
        return Collections.emptySet();
    }
}
