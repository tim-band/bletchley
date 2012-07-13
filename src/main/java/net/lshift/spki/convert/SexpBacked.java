package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.sexpform.Sexp;

public class SexpBacked
    implements Writeable {
    private Sexp sexp;
    private static final Field SEXP_FIELD = getSexpField();

    private static Field getSexpField()
    {
        try {
            return SexpBacked.class.getDeclaredField("sexp");
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings({ "cast", "unchecked" })
    @Override
    public synchronized Sexp toSexp() {
        if (sexp == null) {
            sexp = ((Converter<Object>) ConverterCache.getConverter(
                (Class<Object>)(Class<?>)getClass())).write(this);
        }
        return sexp;
    }


    protected synchronized void setSexp(final Sexp sexp) {
        if (this.sexp == null)
            this.sexp = sexp;
    }

    static Map<Field, Object> getResMap(Sexp sexp)
    {
        Map<Field, Object> res = new HashMap<Field, Object>();
        res.put(SEXP_FIELD, sexp);
        return res;
    }
}
