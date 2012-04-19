package net.lshift.spki.convert.openable;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.CharacterCodingException;

import net.lshift.spki.convert.ConvertUtils;

/**
 * In-memory Openable.
 */
public class ByteOpenable
    implements Openable
{
    private ByteArrayOutputStream output = null;

    @Override
    public InputStream read()
    {
        return new ByteArrayInputStream(output.toByteArray());
    }

    @Override
    public OutputStream write()
    {
        output = new ByteArrayOutputStream();
        return output;
    }

    @Override
    public String toString() {
        try {
            return ConvertUtils.decodeUtf8(output.toByteArray());
        } catch (CharacterCodingException e) {
            throw new RuntimeException(e);
        }
    }
}
