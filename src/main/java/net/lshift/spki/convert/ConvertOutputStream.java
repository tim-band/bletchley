package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.Constants;
import net.lshift.spki.SpkiOutputStream;

public class ConvertOutputStream
    extends SpkiOutputStream
{
    private final SpkiOutputStream os;
    private final Registry registry;

    public ConvertOutputStream(SpkiOutputStream os)
    {
        super();
        this.os = os;
        this.registry = Registry.REGISTRY;
    }

    @Override
    public void atom(byte[] bytes, int off, int len)
        throws IOException
    {
        os.atom(bytes, off, len);
    }

    @Override
    public void beginSexp()
        throws IOException
    {
        os.beginSexp();
    }


    @Override
    public void close()
        throws IOException
    {
        os.close();
    }

    @Override
    public void endSexp()
        throws IOException
    {
        os.endSexp();
    }

    public void atom(String string) throws IOException
    {
        os.atom(string.getBytes(Constants.UTF8));
    }

    public <T> void write(Class<T> clazz, T o) throws IOException {
        registry.getConverter(clazz).write(this, o);
    }

    @SuppressWarnings("unchecked")
    public <T> void writeUnchecked(Class<?> clazz, Object o)
        throws IOException
    {
        ((Converter<Object>) registry.getConverter(clazz)).write(this, o);
    }
}
