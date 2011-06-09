package net.lshift.spki.convert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.lshift.spki.InvalidInputException;

import org.apache.commons.io.IOUtils;

/**
 * Utilities for acting on Openable objects
 */
public class OpenableUtils {
    public static byte[] readBytes(final Openable message)
        throws IOException {
        final InputStream is = message.read();
        try {
            return IOUtils.toByteArray(is);
        } finally {
            is.close();
        }
    }

    public static void writeBytes(final byte[] messageBytes, final Openable out)
        throws IOException {
        final OutputStream os = out.write();
        try {
            os.write(messageBytes);
        } finally {
            os.close();
        }
    }

    public static <T> T read(final Class<T> clazz, final Openable open)
        throws IOException, InvalidInputException {
        return ConvertUtils.read(clazz, open.read());
    }

    public static <T> void write(final Class<T> clazz, final T o, final Openable open)
        throws IOException {
        ConvertUtils.write(clazz, o, open.write());
    }
}
