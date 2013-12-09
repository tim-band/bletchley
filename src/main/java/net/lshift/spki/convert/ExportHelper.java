package net.lshift.spki.convert;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This is a helper which converts anything that has a BeanConverter into
 * a Map. StepConverters are also applied recursively. This is just enough to
 * to produce a data structure to be processed by a JSON generator or
 * Free marker, for example. This has the down side 
 */
@SuppressWarnings({ "rawtypes", "unchecked" })
public class ExportHelper {

    private static final Set<Class<?>> PRIMITIVE;

    static {
        Set<Class<?>> primitive = new HashSet();
        primitive.add(String.class);
        primitive.add(Boolean.class);
        primitive.add(Byte.class);
        primitive.add(Character.class);
        primitive.add(Short.class);
        primitive.add(Integer.class);
        primitive.add(Float.class);
        primitive.add(Double.class);
        primitive.add(BigInteger.class);
        primitive.add(BigDecimal.class);
        PRIMITIVE = Collections.unmodifiableSet(primitive);
    }

    public interface ObjectFactory {
        public Object create(Class<?> clazz, String name, Map<String, Object> fields);
    }

    public static Object export(Object convertable, ObjectFactory factory) {
        Class<? extends Object> clazz = convertable.getClass();
        Converter<?> converter = Registry.getConverter(clazz);
        if(PRIMITIVE.contains(clazz)) {
            return convertable;
        } else if(converter instanceof StepConverter) {
            StepConverter sc = (StepConverter)converter;
            return export(sc.stepIn(convertable), factory);
        } else if(converter instanceof BeanFieldConverter) {
            BeanFieldConverter<?> nbc = (BeanFieldConverter<?>)converter;
            Map<String, Object> fields = new HashMap<String, Object>();
            for(FieldConvertInfo field: nbc.fields) {
                try {
                    fields.put(field.name, export(field.field.get(convertable), factory));
                } catch (IllegalAccessException e) {
                    throw new ConvertReflectionException(converter, clazz, e);
                }
            }

            return factory.create(clazz, nbc.name, fields);
        } else if(converter instanceof SequenceConverter) {
            SequenceConverter sc = (SequenceConverter)converter;
            List<Object> list = new ArrayList();
            List<?> property;
            try {
                property = (List<?>) sc.clazz.getField(sc.beanName).get(convertable);
            } catch (IllegalAccessException e) {
                throw new ConvertReflectionException(converter, clazz, e);
            } catch (NoSuchFieldException e) {
                throw new ConvertReflectionException(converter, clazz, e);
            }
            for (final Object v: property) {
                list.add(export(v, factory));
            }
            return list;
        } else {
            return convertable;
        }
    }
}
