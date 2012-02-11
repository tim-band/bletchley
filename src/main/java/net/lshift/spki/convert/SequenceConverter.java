package net.lshift.spki.convert;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * Converter for a class that has a single field of type List.
 */
public class SequenceConverter<T>
    extends BeanConverter<T> {
    private final String beanName;
    private final Class<?> contentType;

    public SequenceConverter(final Class<T> clazz, final String name, final Field field) {
        super(clazz, name);
        beanName = field.getName();
        if (!(field.getGenericType() instanceof ParameterizedType)) {
            throw new ConvertReflectionException(clazz,
                "Field must be parameterized List type");
        }
        final ParameterizedType pType = (ParameterizedType) field.getGenericType();
        if (!List.class.equals(pType.getRawType())) {
            throw new ConvertReflectionException(clazz,
                "Constructor argument must be List type");
        }
        final Type[] typeArgs = pType.getActualTypeArguments();
        if (typeArgs.length != 1) {
            throw new ConvertReflectionException(clazz,
                "Constructor type must have one parameter");
        }
        contentType = (Class<?>) typeArgs[0];
    }

    @Override
    public void write(final ConvertOutputStream out, final T o)
        throws IOException {
        try {
            out.beginSexp();
            writeName(out);
            final List<?> property = (List<?>) clazz.getField(beanName).get(o);
            for (final Object v: property) {
                out.writeUnchecked(contentType, v);
            }
            out.endSexp();
        } catch (final IllegalAccessException e) {
            throw new ConvertReflectionException(clazz, e);
        } catch (final NoSuchFieldException e) {
            throw new ConvertReflectionException(clazz, e);
        }
    }

    @Override
    public T readRest(final ConvertInputStream in)
        throws IOException, InvalidInputException {
        final List<Object> components = new ArrayList<Object>();
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
                    final Map<Field, Object> fields = new HashMap<Field, Object>();
                    fields.put(clazz.getDeclaredField(beanName), components);
                    return DeserializingConstructor.make(clazz, fields);
                } catch (final InstantiationException e) {
                    throw new ConvertReflectionException(clazz, e);
                } catch (final IllegalAccessException e) {
                    throw new ConvertReflectionException(clazz, e);
                } catch (final NoSuchFieldException e) {
                    throw new ConvertReflectionException(clazz, e);
                }
            case EOF:
                throw new ParseException("Unexpected EOF");
            }
        }
    }
}
