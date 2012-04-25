package net.lshift.spki.convert;

import net.lshift.spki.sexpform.Sexp;

public class SexpBacked
    implements Writeable {
    private Sexp sexp;

    @SuppressWarnings({ "cast", "unchecked" })
    @Override
    public Sexp toSexp() {
        if (sexp == null) {
            sexp = ((Converter<Object>) Registry.getConverter(
                (Class<Object>)(Class<?>)getClass())).write(this);
        }
        return sexp;
    }
}
