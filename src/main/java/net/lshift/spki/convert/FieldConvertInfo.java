package net.lshift.spki.convert;

import org.apache.commons.lang.StringUtils;

public class FieldConvertInfo
{
    protected final String name;
    protected final Class<?> type;
    private final String hyphenatedName;

    public FieldConvertInfo(String name, Class<?> type)
    {
        super();
        this.name = name;
        this.type = type;
        String[] c = StringUtils.splitByCharacterTypeCamelCase(name);
        for (int i = 0; i < c.length; i++) {
            c[i] = StringUtils.lowerCase(c[i]);
        }
        hyphenatedName = StringUtils.join(c, '-');
    }

    public String getName()
    {
        return name;
    }

    public Class<?> getType()
    {
        return type;
    }

    public String getHyphenatedName()
    {
        return hyphenatedName;
    }
}
