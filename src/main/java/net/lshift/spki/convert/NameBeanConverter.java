package net.lshift.spki.convert;

import static net.lshift.spki.Create.atom;

import java.util.List;

import net.lshift.spki.Atom;
import net.lshift.spki.Create;
import net.lshift.spki.Sexp;
import net.lshift.spki.Slist;

/**
 * SExp converter that produces a SExp that looks like key-value pairs
 */
public class NameBeanConverter<T>
    extends BeanFieldConverter<T>
{
    public NameBeanConverter(Class<T> clazz)
    {
        super(clazz);
    }

    @Override
    protected Sexp fieldToSexp(FieldConvertInfo fieldConvertInfo, Sexp sexp)
    {
        return Create.list(fieldConvertInfo.getHyphenatedName(), sexp);
    }

    @Override
    protected Sexp getSExp(
        FieldConvertInfo fieldConvertInfo,
        int i,
        Slist slist)
    {
        String fieldName = fieldConvertInfo.getHyphenatedName();
        Atom match = atom(fieldName);
        for (Sexp s: slist.getSparts()) {
            if (s instanceof Slist) {
                Slist sl = (Slist) s;
                if (match.equals(sl.getHead())) {
                    List<Sexp> sparts = sl.getSparts();
                    if (sparts.size() != 1) {
                        throw new ConvertException(
                            "Wrong number of parts for " + fieldName);
                    }
                    return sparts.get(0);
                }
            }
        }
        throw new ConvertException("No sexp with key " + fieldName
                + " found in sexp " + slist.getHead());
    }
}
