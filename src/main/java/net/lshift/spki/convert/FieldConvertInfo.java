package net.lshift.spki.convert;

import java.lang.reflect.Field;

import org.apache.commons.lang.StringUtils;

/**
 * Information stored by the BeanConverter for each field of the class.
 */
class FieldConvertInfo {
    public final String name;
    public final String hyphenatedName;
    public final Field field;
    public final boolean nullable;
    public final Class<?> inlineListType;

    public FieldConvertInfo(final Class<?> clazz, final Field field)
            throws SecurityException {
        this.field = field;
        this.field.setAccessible(true);
        this.name = field.getName();
        final String[] c = StringUtils.splitByCharacterTypeCamelCase(name);
        for (int i = 0; i < c.length; i++) {
            c[i] = StringUtils.lowerCase(c[i]);
        }
        hyphenatedName = StringUtils.join(c, '-');
        nullable = field.getAnnotation(Convert.Nullable.class) != null;
        inlineListType = findListContentTypeOrNull(clazz, field);
    }

    private static Class<?> findListContentTypeOrNull(
            final Class<?> clazz,
            final Field field) {
        try {
            return SequenceConverter.getTypeInList(clazz, field);
        } catch (ConvertReflectionException e) {
            return null;
        }
    }
}
