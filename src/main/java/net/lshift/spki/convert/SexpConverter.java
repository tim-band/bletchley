package net.lshift.spki.convert;

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

}
