package net.lshift.spki.convert;

import org.apache.commons.lang.StringUtils;

/**
 * Information stored by the BeanConverter for each field of the class.
 */
public class FieldConvertInfo {
    private final int index;
    private final String name;
    private final Class<?> type;
    private final String hyphenatedName;

    public FieldConvertInfo(int index, String name, Class<?> type) {
        super();
        this.index = index;
        this.name = name;
        this.type = type;
        String[] c = StringUtils.splitByCharacterTypeCamelCase(name);
        for (int i = 0; i < c.length; i++) {
            c[i] = StringUtils.lowerCase(c[i]);
        }
        hyphenatedName = StringUtils.join(c, '-');
    }

    public String getName() {
        return name;
    }

    public Class<?> getType() {
        return type;
    }

    public String getHyphenatedName() {
        return hyphenatedName;
    }

    public int getIndex() {
        return index;
    }
}
