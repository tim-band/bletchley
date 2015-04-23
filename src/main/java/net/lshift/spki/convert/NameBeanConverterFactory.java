package net.lshift.spki.convert;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * Use a NameBeanConverter for this class
 */
public class NameBeanConverterFactory
implements ConverterFactory<Convert.ByName>
{
    private static Comparator<Field> FIELD_COMPARATOR = new Comparator<Field>() {
        @Override
        public int compare(Field a, Field b) {
            return a.getName().compareTo(b.getName());
        }
    };

    @Override
    public <T> Converter<T> converter(final Class<T> clazz, final Convert.ByName a) {
        final List<FieldConvertInfo> fields = getFieldMap(clazz);
        return new NameBeanConverter<T>(clazz, a.value(), fields);
    }

    public static <T> List<FieldConvertInfo> getFieldMap(final Class<T> clazz) {
        final List<FieldConvertInfo> fields = new ArrayList<FieldConvertInfo>();
        addFields(clazz, fields);
        return fields;
    }

    public static <T> void addFields(
        final Class<T> clazz,
        final List<FieldConvertInfo> fields) {
        final Class<? super T> sup = clazz.getSuperclass();
        // FIXME: Nasty way to keep "sexp" field out of it
        if (sup != null && sup != SexpBacked.class) {
            addFields(sup, fields);
        }
        Field[] declaredFields = clazz.getDeclaredFields();
        Arrays.sort(declaredFields, FIELD_COMPARATOR);
        for (final Field f: declaredFields) {
            final String fname = f.getName();
            if (!ConvertUtils.isAsciiIdentifier(fname)) {
                throw new IllegalArgumentException();
            }
            if (!fname.startsWith("$") &&
                            (f.getModifiers() & Modifier.STATIC) == 0)
            fields.add(new FieldConvertInfo(clazz, f));
        }
    }
}
