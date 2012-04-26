package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.list;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.sexpform.Slist;


/**
 * Superclass for converters that look for a constructor
 * annotated with the sexp name.
 */
public abstract class BeanConverter<T> extends ConverterImpl<T>
    implements ListConverter<T> {
    protected final String name;

    public BeanConverter(final Class<T> clazz, final String name) {
        super(clazz);
        this.name = name;
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
    public Sexp write(final T o) {
        final List<Sexp> tail = new ArrayList<Sexp>();
        writeRest(o, tail);
        return list(getName(), tail);
    }

    public abstract void writeRest(T o, List<Sexp> tail);

    protected abstract Map<Field, Object> readFields(Converting c, List<Sexp> tail)
        throws InvalidInputException;
}
