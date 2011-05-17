package net.lshift.spki.convert;

import static net.lshift.spki.Create.atom;
import net.lshift.spki.Atom;
import net.lshift.spki.Create;
import net.lshift.spki.SExp;
import net.lshift.spki.SList;

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
    protected SExp fieldToSexp(FieldConvertInfo fieldConvertInfo, SExp sexp)
    {
        return Create.list(fieldConvertInfo.getHyphenatedName(), sexp);
    }

    @Override
    protected SExp getSExp(
        FieldConvertInfo fieldConvertInfo,
        int i,
        SList slist)
    {
        String fieldName = fieldConvertInfo.getHyphenatedName();
        Atom match = atom(fieldName);
        for (SExp s: slist.getSparts()) {
            if (s instanceof SList) {
                SList sl = (SList) s;
                if (match.equals(sl.getHead())) {
                    SExp[] sparts = sl.getSparts();
                    if (sparts.length != 1) {
                        throw new ConvertException(
                            "Wrong number of parts for " + fieldName);
                    }
                    return sparts[0];
                }
            }
        }
        throw new ConvertException("No sexp with key " + fieldName
                + " found in sexp " + slist.getHead());
    }
}
