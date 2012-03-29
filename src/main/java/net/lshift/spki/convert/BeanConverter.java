package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.list;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.sexpform.Slist;

import org.bouncycastle.util.Arrays;

/**
 * Superclass for converters that look for a constructor
 * annotated with the sexp name.
 */
public abstract class BeanConverter<T>
    implements ListConverter<T> {
    protected final Class<T> clazz;
    protected final String name;

    public BeanConverter(final Class<T> clazz, final String name) {
        this.clazz = clazz;
        this.name = name;
    }

    @Override
    public Class<T> getResultClass() {
        return clazz;
    }

    /* (non-Javadoc)
     * @see net.lshift.spki.convert.ListConverter#getName()
     */
    @Override
    public String getName() {
        return name;
    }

    @Override
    public T read(final Converting c, final Sexp in)
        throws InvalidInputException {
            final Slist lin = in.list();
            assertMatches(lin.getHead(), getName());
            return DeserializingConstructor.convertMake(
                clazz, readFields(c, lin.getSparts()));
        }

    @Override
    public Sexp write(final Converting c, final T o) {
        final List<Sexp> tail = new ArrayList<Sexp>();
        writeRest(c, o, tail);
        return list(getName(), tail);
    }

    public abstract void writeRest(Converting c, T o, List<Sexp> tail);

    public static void assertMatches(final Sexp atom, final String name)
                    throws ConvertException {
        assertMatches(atom.atom().getBytes(), name);
    }

    public static void assertMatches(final byte[] bytes, final String name)
        throws ConvertException {
        if (!Arrays.areEqual(ConvertUtils.bytes(name), bytes)) {
            throw new ConvertException("Unexpected name, expected "
                + name + " got " + ConvertUtils.stringOrNull(bytes));
        }
    }

    protected abstract Map<Field, Object> readFields(Converting c, List<Sexp> tail)
        throws InvalidInputException;
}
