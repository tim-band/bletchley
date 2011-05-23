package net.lshift.spki.convert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.lshift.spki.ParseException;

import org.apache.commons.io.IOUtils;

/**
 * Utilities for acting on Openable objects
 */
public class OpenableUtils {
    public static byte[] readBytes(Openable message)
        throws IOException {
        final InputStream is = message.read();
        try {
            return IOUtils.toByteArray(is);
        } finally {
            is.close();
        }
    }

    public static void writeBytes(final byte[] messageBytes, Openable out)
        throws IOException {
        OutputStream os = out.write();
        try {
            os.write(messageBytes);
        } finally {
            os.close();
        }
    }

    public static <T> T read(Class<T> clazz, Openable open)
        throws ParseException,
            IOException {
        return ConvertUtils.read(clazz, open.read());
    }

    public static <T> void write(Class<T> clazz, T o, Openable open)
        throws IOException {
        ConvertUtils.write(clazz, o, open.write());
    }
}
