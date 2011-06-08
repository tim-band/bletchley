package net.lshift.spki.convert;

import java.io.IOException;
import java.io.OutputStream;

import net.lshift.spki.CanonicalSpkiOutputStream;
import net.lshift.spki.SpkiOutputStream;

public class ConvertOutputStream
    extends SpkiOutputStream {
    private final SpkiOutputStream os;
    private final Registry registry;

    public ConvertOutputStream(final SpkiOutputStream os) {
        super();
        this.os = os;
        this.registry = Registry.REGISTRY;
    }

    public ConvertOutputStream(final OutputStream out)
    {
        this(new CanonicalSpkiOutputStream(out));
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
        registry.getConverter(clazz).write(this, o);
    }

    @SuppressWarnings("unchecked")
    public <T> void writeUnchecked(final Class<?> clazz, final Object o)
        throws IOException {
        ((Converter<Object>) registry.getConverter(clazz)).write(this, o);
    }
}
