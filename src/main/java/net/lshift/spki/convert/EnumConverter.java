package net.lshift.spki.convert;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

import net.lshift.spki.InvalidInputException;

public class EnumConverter<T extends Enum<T>>
extends StringStepConverter<T> {
    private static final String VALID_ENUM =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    private final Class<T> resultClass;
    private final Map<T, String> forwardMap
        = new HashMap<T, String>();
    private final Map<String, T> backMap
        = new HashMap<String, T>();

    public EnumConverter(Class<T> resultClass) {
        if (!resultClass.isEnum()) {
            throw new IllegalArgumentException();
        }
        this.resultClass = resultClass;
        for (T t: resultClass.getEnumConstants()) {
            final String name = t.name();
            if (!StringUtils.containsOnly(name, VALID_ENUM)) {
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
    protected T stepOut(String s)
        throws InvalidInputException {
        T res = backMap.get(s);
        if (res == null) {
            throw new ConvertException("not present in enum: " +s);
        }
        return res;
    }

    @Override
    protected String stepIn(T o) {
        return forwardMap.get(o);
    }
}
