package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.SpkiOutputStream;

/**
 * SpkiOutputStream that wraps another SpkiOutputStream to add facilities
 * useful for conversion from classes.
 */
public class ConvertOutputStream
    extends SpkiOutputStream {
    private final SpkiOutputStream os;

    public ConvertOutputStream(final SpkiOutputStream os) {
        super();
        this.os = os;
    }

    @Override
    public void atom(final byte[] bytes, final int off, final int len)
        throws IOException {
        os.atom(bytes, off, len);
    }

    @Override
    public void beginSexp()
        throws IOException {
        os.beginSexp();
    }

    @Override
    public void close()
        throws IOException {
        os.close();
    }

    @Override
    public void endSexp()
        throws IOException {
        os.endSexp();
    }

    public void atom(final String string)
        throws IOException {
        os.atom(ConvertUtils.bytes(string));
    }

    public <T> void write(final Class<T> clazz, final T o) throws IOException {
        Registry.getConverter(clazz).write(this, o);
    }

    @SuppressWarnings("unchecked")
    public <T> void writeUnchecked(final Class<?> clazz, final Object o)
        throws IOException {
        //System.out.println("Converting " + clazz.getCanonicalName());
        ((Converter<Object>) Registry.getConverter(clazz)).write(this, o);
        //System.out.println("Converted " + clazz.getCanonicalName());
    }
}
