package net.lshift.spki.convert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * In-memory Openable suitable only for testing.
 */
public class ByteOpenable
    implements Openable
{
    private final ByteArrayOutputStream output = new ByteArrayOutputStream();

    @Override
    public InputStream read()
    {
        return new ByteArrayInputStream(output.toByteArray());
    }

    @Override
    public OutputStream write()
    {
        return output;
    }

}
