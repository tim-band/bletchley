package net.lshift.spki.convert;

import org.apache.commons.lang.StringUtils;

/**
 * Information stored by the BeanConverter for each field of the class.
 */
class FieldConvertInfo {
    public final int index;
    public final String name;
    public final Class<?> type;
    public final String hyphenatedName;

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
}
