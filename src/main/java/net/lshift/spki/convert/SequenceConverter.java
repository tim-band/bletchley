package net.lshift.spki.convert;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * Converter for a class that has a single field of type List.
 */
public class SequenceConverter<T>
    extends BeanConverter<T> {
    private final String beanName;
    private final Class<?> contentType;

    public SequenceConverter(Class<T> clazz, String name) {
        super(clazz, name);
        Field[] fields = clazz.getDeclaredFields();
        if (fields.length != 1) {
            throw new ConvertReflectionException(clazz,
                "Class must have one field");
        }
        beanName = fields[0].getName();
        if (!(fields[0].getGenericType() instanceof ParameterizedType)) {
            throw new ConvertException(
                "Field must be parameterized List type:"
                + clazz.getCanonicalName());
        }
        ParameterizedType pType = (ParameterizedType) fields[0].getGenericType();
        if (!List.class.equals(pType.getRawType())) {
            throw new ConvertException(
                "Constructor argument must be List type:"
                + clazz.getCanonicalName());
        }
        Type[] typeArgs = pType.getActualTypeArguments();
        if (typeArgs.length != 1) {
            throw new ConvertException(
                "Constructor type must have one parameter"
                + clazz.getCanonicalName());
        }
        contentType = (Class<?>) typeArgs[0];
    }

    @Override
    public void write(ConvertOutputStream out, T o)
        throws IOException {
        try {
            out.beginSexp();
            writeName(out);
            List<?> property = (List<?>) clazz.getField(beanName).get(o);
            for (Object v: property) {
                out.writeUnchecked(contentType, v);
            }
        out.endSexp();
        } catch (IllegalAccessException e) {
            throw new ConvertReflectionException(e);
        } catch (NoSuchFieldException e) {
            throw new ConvertReflectionException(e);
        }
    }

    @Override
    public T read(ConvertInputStream in)
        throws ParseException,
            IOException {
        in.nextAssertType(TokenType.OPENPAREN);
        in.assertAtom(name);
        List<Object> components = new ArrayList<Object>();
        for (;;) {
            final TokenType token = in.next();
            switch (token) {
            case ATOM:
            case OPENPAREN:
                in.pushback(token);
                components.add(in.read(contentType));
                break;
            case CLOSEPAREN:
                try {
                    Map<Field, Object> fields = new HashMap<Field, Object>();
                    fields.put(clazz.getDeclaredField(beanName), components);
                    return DeserializingConstructor.make(clazz, fields);
                } catch (InstantiationException e) {
                    throw new ConvertReflectionException(e);
                } catch (IllegalAccessException e) {
                    throw new ConvertReflectionException(e);
                } catch (SecurityException e) {
                    throw new ConvertReflectionException(e);
                } catch (IllegalArgumentException e) {
                    throw new ConvertReflectionException(e);
                } catch (NoSuchFieldException e) {
                    throw new ConvertReflectionException(e);
                }
            default:
                throw new ParseException("Unexpected token in sequence");
            }
        }
    }
}
