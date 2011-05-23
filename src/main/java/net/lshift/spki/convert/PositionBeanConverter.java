package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.SpkiInputStream.TokenType;

/**
 * SExp converter that lists the bean fields in a fixed order.
 */
public class PositionBeanConverter<T>
    extends BeanFieldConverter<T> {
    public PositionBeanConverter(Class<T> clazz) {
        super(clazz);
    }

    @Override
    protected void writeField(
        ConvertOutputStream out,
        FieldConvertInfo field,
        Object property)
        throws IOException {
        out.writeUnchecked(field.getType(), property);
    }

    @Override
    protected void read(ConvertInputStream in, Object[] initargs)
        throws ParseException,
            IOException {
        in.nextAssertType(TokenType.OPENPAREN);
        in.assertAtom(name);
        for (int i = 0; i < fields.length; i++) {
            initargs[i] = in.read(fields[i].getType());
        }
        in.nextAssertType(TokenType.CLOSEPAREN);
    }
}
