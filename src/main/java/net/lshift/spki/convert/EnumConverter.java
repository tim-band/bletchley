package net.lshift.spki.convert;

import java.util.HashMap;
import java.util.Map;

import net.lshift.spki.InvalidInputException;

import org.apache.commons.lang.StringUtils;

public class EnumConverter<T extends Enum<T>>
extends StringStepConverter<T> {
    private static final String VALID_ENUM_FIRST =
       "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String VALID_ENUM =
       "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    private final Class<T> resultClass;
    private final Map<T, String> forwardMap
        = new HashMap<T, String>();
    private final Map<String, T> backMap
        = new HashMap<String, T>();

    public EnumConverter(final Class<T> resultClass) {
        if (!resultClass.isEnum()) {
            throw new IllegalArgumentException();
        }
        this.resultClass = resultClass;
        for (final T t: resultClass.getEnumConstants()) {
            final String name = t.name();
            if (!StringUtils.containsOnly(name, VALID_ENUM) || 
                VALID_ENUM_FIRST.indexOf(name.charAt(0)) < 0) {
                throw new IllegalArgumentException(
                    "Enum contains non-standard name: " + name);
            }
            final String conversion = name.toLowerCase().replace('_', '-');
            forwardMap.put(t, conversion);
            backMap.put(conversion, t);
        }
    }

    @Override public Class<T> getResultClass() { return resultClass; }

    @Override
    protected T stepOut(final String s)
        throws InvalidInputException {
        final T res = backMap.get(s);
        if (res == null) {
            throw new ConvertException("not present in enum: " +s);
        }
        return res;
    }

    @Override
    protected String stepIn(final T o) {
        return forwardMap.get(o);
    }
}
