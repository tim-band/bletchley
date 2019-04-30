package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.list;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.sexpform.Slist;

/**
 * SExp converter that produces a SExp that looks like key-value pairs
 */
public class NameBeanConverter<T>
    extends BeanFieldConverter<T> {
    public NameBeanConverter(
        final Class<T> clazz,
        final String name,
        final List<FieldConvertInfo> fields) {
        super(clazz, name, fields);
    }

    @Override
    protected Sexp writeField(
        final FieldConvertInfo field,
        final Object property) {
        if (property != null) {
            if (field.inlineListType == null) {
                return list(field.hyphenatedName,
                        writeUnchecked(field.field.getType(), property));
            } else {
                return writeListField(field, property);
            }
        } else if (field.nullable) {
            return null;
        } else {
            throw new NullPointerException(
                "Field not marked as nullable is null: " +
                clazz.getCanonicalName() + "." + field.name);
        }
    }

    private Sexp writeListField(final FieldConvertInfo field,
            final Object property) {
        List<?> list = (List<?>)property;
        Sexp [] tail = new Sexp[list.size()];
        for(int i = 0; i != list.size(); ++i) {
            tail[i] = writeUnchecked(field.inlineListType, list.get(i));
        }
        return list(field.hyphenatedName, tail);
    }

    @Override
    protected Map<Field, Object> readFields(final ConverterCatalog r, final Slist tail)
        throws InvalidInputException {
        final Map<Field, Object> res = new HashMap<>();
        for (final Sexp s: tail.getSparts()) {
            final Slist ls = s.list();
            final FieldConvertInfo field = getField(ls.getHead().getBytes());
            if (res.containsKey(field.field)) {
                throw new ConvertException("Repeated field");
            }
            final List<Sexp> ltail = ls.getSparts();
            if(field.inlineListType == null) {
                if (ltail.size() != 1) {
                    throw new ConvertException("multiple parts to named field");
                }
                res.put(field.field,
                        readElement(field.field.getType(), r, ltail.get(0)));
            } else {
                res.put(field.field, readSequence(r, field.inlineListType, ltail));
            }
        }
        for (final FieldConvertInfo field: fields) {
            if (!res.containsKey(field.field) && !field.nullable) {
                throw new ConvertException("Missing field: " + field.hyphenatedName);
            }
        }
        return res;
    }

    private FieldConvertInfo getField(final byte[] bytes)
        throws ConvertException {
        final String string = ConvertUtils.stringOrNull(bytes);
        for (final FieldConvertInfo field: fields) {
            if (field.hyphenatedName.equals(string)) {
                return field;
            }
        }
        throw new ConvertException("No field matching name found: " + string);
    }
}
