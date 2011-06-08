package net.lshift.spki.convert;

import java.lang.reflect.Field;

import org.apache.commons.lang.StringUtils;

/**
 * Information stored by the BeanConverter for each field of the class.
 */
class FieldConvertInfo {
    public final int index;
    public final String name;
    public final Class<?> type;
    public final String hyphenatedName;
    public final Field field;

    public FieldConvertInfo(Class<?> clazz, int index, String name, Class<?> type)
    throws SecurityException, NoSuchFieldException {
        super();
        this.index = index;
        this.name = name;
        this.type = type;
        String[] c = StringUtils.splitByCharacterTypeCamelCase(name);
        for (int i = 0; i < c.length; i++) {
            c[i] = StringUtils.lowerCase(c[i]);
        }

        hyphenatedName = StringUtils.join(c, '-');



        Class<?> searchtype = clazz;
        Field field = null;
        while(searchtype != Object.class) {
            try {
                field = searchtype.getDeclaredField(name);
                break;
            }
            catch(NoSuchFieldException e) {
                searchtype = searchtype.getSuperclass();
            }
        }

        this.field = field == null ? type.getDeclaredField(name) : field;
        this.field.setAccessible(true);
    }


}
