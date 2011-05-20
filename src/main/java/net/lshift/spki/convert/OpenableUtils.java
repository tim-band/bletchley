package net.lshift.spki.convert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.lshift.spki.CanonicalSpkiOutputStream;
import net.lshift.spki.Marshal;
import net.lshift.spki.ParseException;

import org.apache.commons.io.IOUtils;

/**
 * Utilities for acting on Openable objects
 */
public class OpenableUtils
{
    public static byte[] readBytes(Openable message)
        throws IOException
    {
        final InputStream is = message.read();
        try {
            return IOUtils.toByteArray(is);
        } finally {
            is.close();
        }
    }

    public static void writeBytes(Openable out, final byte[] messageBytes)
        throws IOException
    {
        OutputStream os = out.write();
        try {
            os.write(messageBytes);
        } finally {
            os.close();
        }
    }

    public static <T> T read(Class<T> clazz, Openable open)
        throws ParseException,
            IOException
    {
        final InputStream is = open.read();
        try {
            return Convert.fromSExp(clazz, Marshal.unmarshal(is));
        } finally {
            is.close();
        }
    }

    public static <T> void write(Openable open, Class<T> clazz, T o)
        throws IOException
    {
        final OutputStream os = open.write();
        try {
            ConvertOutputStream out
                = new ConvertOutputStream(new CanonicalSpkiOutputStream(os));
            out.write(clazz, o);
            out.close();
        } finally {
            os.close();
        }
    }
}
