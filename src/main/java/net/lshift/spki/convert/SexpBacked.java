package net.lshift.spki.convert;

import net.lshift.spki.sexpform.Sexp;

public class SexpBacked
        implements Writeable {

    @SuppressWarnings({ "cast", "unchecked" })
    @Override
    public synchronized Sexp toSexp() {
        return (ConverterCache.getConverter((Class<Object>)(Class<?>)getClass())).write(this);
    }
}
