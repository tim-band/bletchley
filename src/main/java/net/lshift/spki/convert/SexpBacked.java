package net.lshift.spki.convert;

import net.lshift.spki.sexpform.Sexp;

public class SexpBacked
    implements Writeable {

    @SuppressWarnings({ "cast", "unchecked" })
    @Override
    public Sexp toSexp() {
        return ((Converter<Object>) Registry.getConverter(
            (Class<Object>)(Class<?>)getClass())).write(this);
    }

}
