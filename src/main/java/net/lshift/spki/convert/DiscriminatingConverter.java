package net.lshift.spki.convert;

import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.SExp;
import net.lshift.spki.SList;

public class DiscriminatingConverter<T> implements Converter<T>
{
    private final Map<String, Converter<? extends T>> nameMap
        = new HashMap<String, Converter<? extends T>>();
    private final HashMap<Class<? extends T>, Converter<? extends T>> classMap
        = new HashMap<Class<? extends T>, Converter<? extends T>>();

    public DiscriminatingConverter(Class<? extends T>... classes)
    {
        for (Class<? extends T> clazz: classes) {
            Converter<? extends T> converter
                = Convert.REGISTRY.getConverter(clazz);
            classMap.put(clazz, converter);
            nameMap.put(
                ((BeanConverter<? extends T>) converter).getName(),
                converter);
        }
    }

    @Override
    public T fromSexp(SExp sexp)
    {
        // FIXME: better error handling
        Converter<? extends T> converter
            = nameMap.get(ConvertUtils.toString(((SList)sexp).getHead()));
        return converter.fromSexp(sexp);
    }

    @SuppressWarnings("unchecked")
    @Override
    public SExp toSexp(T o)
    {
        return ((Converter<T>)classMap.get(o.getClass())).toSexp(o);
    }
}
