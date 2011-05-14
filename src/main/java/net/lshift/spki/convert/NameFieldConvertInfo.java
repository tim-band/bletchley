package net.lshift.spki.convert;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.Create.list;

import java.lang.reflect.InvocationTargetException;

import net.lshift.spki.Atom;
import net.lshift.spki.SExp;
import net.lshift.spki.SList;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.lang.StringUtils;

public class NameFieldConvertInfo
    extends FieldConvertInfo
{
    private final String hyphenatedName;

    public NameFieldConvertInfo(String name, Class<?> type)
    {
        super(name, type);
        String[] c = StringUtils.splitByCharacterTypeCamelCase(name);
        for (int i = 0; i < c.length; i++) {
            c[i] = StringUtils.lowerCase(c[i]);
        }
        hyphenatedName = StringUtils.join(c, '-');
    }

    @Override
    public SExp genSexp(Object bean)
        throws IllegalAccessException,
            InvocationTargetException,
            NoSuchMethodException
    {
        return list(hyphenatedName, Convert.toSExp(
            PropertyUtils.getProperty(bean, name)));
    }

    @Override
    public SExp getValueSExp(SExp sexp) {
        SExp[] sexpVal = getSExp(hyphenatedName, sexp).getSparts();
        assert sexpVal.length == 1;
        return sexpVal[0];
    }

    private static SList getSExp(String string, SExp sexp) {
        Atom match = atom(string);
        for (SExp s: ((SList)sexp).getSparts()) {
            if (s instanceof SList) {
                SList sl = (SList) s;
                if (match.equals(sl.getHead())) {
                    return sl;
                }
            }
        }
        throw new ConvertException("No sexp with key " + string
                + " found in sexp " + ((SList)sexp).getHead().getBytes());
    }
}
